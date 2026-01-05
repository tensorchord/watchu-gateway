//go:build amd64 && linux

package sslsniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
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
	mu       sync.Mutex
	probs    []TLSProbe
	client   *collector.GatewayClient
	reqChan  chan *collector.RawRequest
	respChan chan *collector.RawResponse
}

func NewSSLProbe(sslPath, rustlsPath *string, client *collector.GatewayClient) *SSLProbe {
	probs := []TLSProbe{}

	// OpenSSL
	libsslPaths := []string{}
	if sslPath != nil && len(*sslPath) > 0 {
		if ok, err := tool.IsFilePath(*sslPath); err != nil || !ok {
			log.Panic().Str("path", *sslPath).Err(err).Msg("invalid SSL library path")
		}
		libsslPaths = append(libsslPaths, *sslPath)
	}
	commonLibsslPath, err := findLibOpenSSLPath()
	if err != nil {
		log.Warn().Err(err).Msg("failed to detect the common libssl paths")
	} else {
		libsslPaths = append(libsslPaths, commonLibsslPath)
	}
	for i, path := range libsslPaths {
		prob, err := NewOpenSSLProbe(path)
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("failed to create OpenSSL probe")
			continue
		}
		if prob != nil {
			log.Info().Int("index", i).Str("path", path).Msg("attached OpenSSL library")
			probs = append(probs, prob)
		}
	}

	// TODO: rustls
	rustls, err := NewRusTLSProbe(rustlsPath)
	if err != nil {
		log.Panic().Err(err).Msg("failed to create rustls probe")
	}
	if rustls != nil {
		probs = append(probs, rustls)
	}

	return &SSLProbe{
		probs:    probs,
		client:   client,
		reqChan:  make(chan *collector.RawRequest, collector.GatewayChannelSize),
		respChan: make(chan *collector.RawResponse, collector.GatewayChannelSize),
	}
}

func handle(i int, prob TLSProbe, store *SSLStore) {
	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Int("rb_index", i).Value()
	logger.Info().Msg("#############")
	var event sslEvent

	for {
		record, err := prob.ReadBuffer()
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
			var data, protocol string
			if isHTTP2Protocol(event.Data[:event.DataLen]) {
				data = hex.EncodeToString(event.Data[:event.DataLen])
				protocol = "HTTP/2"
			} else {
				data = string(event.Data[:event.DataLen])
				protocol = "HTTP/1"
			}
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
				Str("data", data).
				Str("protocol", protocol).
				Msg("HTTP event")
		}
	}
}

func (sp *SSLProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for SSL read/write events...")

	go sp.client.IngestRequestEvent(ctx, sp.reqChan)
	go sp.client.IngestResponseEvent(ctx, sp.respChan)
	store := NewSSLStore()
	go store.Parse(ctx, sp.reqChan, sp.respChan)

	var wg sync.WaitGroup
	for i, prob := range sp.probs {
		wg.Go(func() { handle(i, prob, store) })
	}

	// dynamic probe
	channel := make(chan container.ContainerOpenSSL, MAX_DYNAMIC_CHANNEL_SIZE)
	go container.NewContainerLibsDetector().Start(ctx, channel)
	dynamicProbes := make(map[container.LibKey]string)
	for containerLibs := range channel {
		for key, path := range containerLibs.Libs {
			_, exist := dynamicProbes[key]
			if exist {
				continue
			}
			prob, err := NewOpenSSLProbe(path)
			if err != nil {
				log.Error().Err(err).Str("path", path).Any("key", key).Msg("failed to probe the SSL lib")
				continue
			}
			// There is no Time-of-Check to Time-of-Use (TOCTOU) issue here.
			index := len(sp.probs)
			log.Info().Int("index", index).Str("path", path).Any("key", key).Msg("attaching dynamic SSL uprobes")
			sp.mu.Lock()
			dynamicProbes[key] = path
			wg.Go(func() { handle(index, prob, store) })
			sp.probs = append(sp.probs, prob)
			sp.mu.Unlock()
		}
	}

	wg.Wait()
	log.Info().Msg("SSLProbe closed")
}

func (sp *SSLProbe) Close() {
	sp.mu.Lock()
	for i, prob := range sp.probs {
		if err := prob.Close(); err != nil {
			log.Error().Err(err).Int("probe_index", i).Msg("failed to close TLS probe")
		}
		log.Info().Int("probe_index", i).Msg("SSL probe closed successfully")
	}
	sp.mu.Unlock()
	close(sp.reqChan)
	close(sp.respChan)
}
