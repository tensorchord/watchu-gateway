//go:build amd64 && linux

package sslsniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector"
	"github.com/tensorchord/watchu/collector/internal/container"
	"github.com/tensorchord/watchu/collector/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ssl ssl.bpf.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 rustls rustls.bpf.c -- -I../headers

const (
	sslSpecPath    = "sslsniff/ssl_x86_bpfel.o"
	rustlsSpecPath = "sslsniff/rustls_x86_bpfel.o"
)

type TLSProbe interface {
	ReadBuffer() (ringbuf.Record, error)
	Close() error
}

type SSLProbe struct {
	mu           sync.Mutex // lock the probes
	probes       map[container.LibKey]TLSProbe
	client       *collector.GatewayClient
	reqChan      chan *collector.RawRequest
	respChan     chan *collector.RawResponse
	postgresChan chan *collector.RawPostgres
}

func NewSSLProbe(sslPath, rustlsPath *string, client *collector.GatewayClient) *SSLProbe {
	probes := make(map[container.LibKey]TLSProbe)

	// OpenSSL
	libsslPaths := []string{}
	commonLibsslPath, err := findLibOpenSSLPath()
	if err != nil {
		log.Warn().Err(err).Msg("failed to detect the common libssl paths")
	} else {
		libsslPaths = append(libsslPaths, commonLibsslPath)
	}
	if sslPath != nil && len(*sslPath) > 0 {
		if ok, err := tool.IsFilePath(*sslPath); err != nil || !ok {
			log.Panic().Str("path", *sslPath).Err(err).Msg("invalid SSL library path")
		}
		libsslPaths = append(libsslPaths, *sslPath)
	}
	for i, path := range libsslPaths {
		key, err := container.FindLibKey(path)
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("failed to find lib key")
			continue
		}
		if _, exist := probes[*key]; exist {
			continue
		}
		probe, err := NewOpenSSLProbe(path)
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("failed to create OpenSSL probe")
			continue
		}
		if probe != nil {
			log.Info().Any("key", key).Int("index", i).Str("path", path).Msg("attached OpenSSL library")
			probes[*key] = probe
		}
	}

	// TODO: rustls
	rustls, err := NewRusTLSProbe(rustlsPath)
	if err != nil {
		log.Panic().Err(err).Msg("failed to create rustls probe")
	}
	if rustls != nil {
		key, err := container.FindLibKey(*rustlsPath)
		if err != nil {
			log.Panic().Err(err).Str("path", *rustlsPath).Msg("failed to find rustls lib key")
		}
		probes[*key] = rustls
	}

	return &SSLProbe{
		probes:       probes,
		client:       client,
		reqChan:      make(chan *collector.RawRequest, collector.GatewayChannelSize),
		respChan:     make(chan *collector.RawResponse, collector.GatewayChannelSize),
		postgresChan: make(chan *collector.RawPostgres, collector.GatewayChannelSize),
	}
}

func handle(key container.LibKey, probe TLSProbe, store *SSLStore) {
	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Any("key", key).Value()
	var event sslEvent

	for {
		record, err := probe.ReadBuffer()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Info().Msg("SSL ringbuf closed")
				return
			}
			logger.Warn().Err(err).Msg("read from ringbuffer error")
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Error().Err(err).Msg("parsing ssl ringbuf record")
			continue
		}

		store.Add(&event)
		if logger.Debug().Enabled() {
			data := event.Data[:event.DataLen]
			logger.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("req_len", event.ReqLen).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("cgroup_id", event.CgroupId).
				Uint64("*SSL", event.SslPtr).
				Uint64("data_len", event.DataLen).
				Uint8("rw", event.Rw).
				Str("comm", tool.CharsToString(event.Comm[:])).
				Bytes("data", data).
				Msg("TLS event")
		}
	}
}

func (sp *SSLProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for SSL read/write events...")

	go sp.client.IngestRequestEvent(ctx, sp.reqChan)
	go sp.client.IngestResponseEvent(ctx, sp.respChan)
	go sp.client.IngestPostgresEvent(ctx, sp.postgresChan)
	store := NewSSLStore()
	go store.Parse(ctx, sp.reqChan, sp.respChan, sp.postgresChan)

	var wg sync.WaitGroup
	for key, probe := range sp.probes {
		wg.Go(func() { handle(key, probe, store) })
	}

	// dynamic probe
	channel := make(chan container.ContainerOpenSSL, MAX_DYNAMIC_CHANNEL_SIZE)
	go container.NewContainerLibsDetector().Start(ctx, channel)
	for containerLibs := range channel {
		for key, path := range containerLibs.Libs {
			// there is no Time-of-Check to Time-of-Use (TOCTOU) here
			sp.mu.Lock()
			_, exist := sp.probes[key]
			sp.mu.Unlock()
			if exist {
				continue
			}
			probe, err := NewOpenSSLProbe(path)
			if err != nil {
				log.Error().Err(err).Str("path", path).Any("key", key).Msg("failed to probe the SSL lib")
				continue
			}
			sp.mu.Lock()
			index := len(sp.probes)
			wg.Go(func() { handle(key, probe, store) })
			sp.probes[key] = probe
			sp.mu.Unlock()
			log.Info().Int("index", index).Str("path", path).Any("key", key).Msg("attaching dynamic SSL uprobes")
		}
	}

	wg.Wait()
	log.Info().Msg("SSLProbe closed")
}

func (sp *SSLProbe) Close() {
	sp.mu.Lock()
	for key, probe := range sp.probes {
		if err := probe.Close(); err != nil {
			log.Error().Err(err).Any("key", key).Msg("failed to close TLS probe")
		}
		log.Info().Any("key", key).Msg("SSL probe closed successfully")
	}
	sp.mu.Unlock()
	close(sp.reqChan)
	close(sp.respChan)
}
