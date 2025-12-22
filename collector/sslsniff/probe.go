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
	"github.com/tensorchord/watchu/collector/internal/tool"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ssl ssl.bpf.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 rustls rustls.bpf.c -- -I../headers

const (
	sslSpecPath    = "sslsniff/ssl_x86_bpfel.o"
	rustlsSpecPath = "sslsniff/rustls_x86_bpfel.o"
)

type TLSProbe interface {
	Start(ctx context.Context)
	ReadBuffer() (ringbuf.Record, error)
	Close() error
}

type SSLProbe struct {
	probs    []TLSProbe
	client   *collector.GatewayClient
	reqChan  chan *collector.RawRequest
	respChan chan *collector.RawResponse
}

func NewSSLProbe(sslPath, rustlsPath *string, client *collector.GatewayClient) *SSLProbe {
	probs := []TLSProbe{}

	openssl, err := NewOpenSSLProbe(sslPath)
	if err != nil {
		log.Panic().Err(err).Msg("failed to create OpenSSL probe")
	}
	if openssl != nil {
		probs = append(probs, openssl)
	}

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

func (sp *SSLProbe) Start(ctx context.Context) {
	log.Info().Msg("listening for SSL read/write events...")
	var event sslEvent
	go sp.client.IngestRequestEvent(ctx, sp.reqChan)
	go sp.client.IngestResponseEvent(ctx, sp.respChan)
	store := NewSSLStore()
	go store.Parse(ctx, sp.reqChan, sp.respChan)

	var wg sync.WaitGroup
	for i, prob := range sp.probs {
		wg.Go(func() {
			logger := log.DefaultLogger
			logger.Context = log.NewContext(nil).Int("rb_index", i).Value()
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
		})
	}
	wg.Wait()
}

func (sp *SSLProbe) Close() {
	for i, prob := range sp.probs {
		if err := prob.Close(); err != nil {
			log.Error().Err(err).Int("index", i).Msg("failed to close TLS probe")
		}
	}
	close(sp.reqChan)
	close(sp.respChan)
}
