//go:build amd64 && linux

package sslsniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ssl ssl.bpf.c -- -I../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 rustls rustls.bpf.c -- -I../headers

const (
	sslSpecPath    = "sslsniff/ssl_x86_bpfel.o"
	rustlsSpecPath = "sslsniff/rustls_x86_bpfel.o"
)

var libSSLCandidates = []string{
	"/lib/x86_64-linux-gnu/libssl.so.1.1", // Ubuntu/Debian
	"/lib/x86_64-linux-gnu/libssl.so.3",   // Newer Ubuntu/Debian
	"/lib64/libssl.so.1.1",                // CentOS/RHEL
	"/lib64/libssl.so.3",                  // Fedora or newer CentOS/RHEL
	"/usr/local/lib/libssl.so",            // Custom builds
}

var libSDirs = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/usr/local/lib",
	"/usr/local/lib64",
}

func isFilePath(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return !st.IsDir(), nil
}

func findLibSSLPath() (string, error) {
	for _, path := range libSSLCandidates {
		if ok, err := isFilePath(path); err == nil && ok {
			return path, nil
		}
	}

	for _, dir := range libSDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "libssl.so*"))
		if len(matches) > 0 {
			log.Info().Str("path", matches[0]).Msg("found potential libssl, consider add this to the env")
			for _, path := range matches {
				if ok, err := isFilePath(path); err == nil && ok {
					return path, nil
				}
			}
		}
	}
	return "", fmt.Errorf("libssl not found, please set the path via args `--ssl-path`")
}

func attachSSLProbes(ex *link.Executable, objs *sslObjects, target string, links *[]link.Link) {
	probes := []struct {
		symbol string
		prog   *ebpf.Program
		inject func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{"SSL_read", objs.ProbeSslReadEntry, ex.Uprobe},
		{"SSL_read", objs.ProbeSslReadExit, ex.Uretprobe},
		{"SSL_read_ex", objs.ProbeSslReadExEntry, ex.Uprobe},
		{"SSL_read_ex", objs.ProbeSslReadExExit, ex.Uretprobe},
		{"SSL_write", objs.ProbeSslReadEntry, ex.Uprobe},
		{"SSL_write", objs.ProbeSslWriteExit, ex.Uretprobe},
		{"SSL_write_ex", objs.ProbeSslReadExEntry, ex.Uprobe},
		{"SSL_write_ex", objs.ProbeSslWriteExExit, ex.Uretprobe},
	}

	failedProbes := 0
	for _, probe := range probes {
		up, err := probe.inject(probe.symbol, probe.prog, nil)
		if err != nil {
			log.Warn().Str("target", target).Err(err).Msgf("failed to attach probe %s", probe.symbol)
			failedProbes++
			continue
		}
		*links = append(*links, up)
	}
	if failedProbes > 0 {
		log.Fatal().Int("failed", failedProbes).Str("target", target).Msg("failed to attach SSL")
	}
}

func addSSLProbe(sslPath *string, links *[]link.Link) *sslObjects {
	attachPaths := []string{}
	libPaths, err := findLibSSLPath()
	if err != nil {
		log.Warn().Err(err).Msg("cannot find the libssl path")
	} else {
		attachPaths = append(attachPaths, libPaths)
	}

	if sslPath != nil && len(*sslPath) > 0 {
		if ok, err := isFilePath(*sslPath); err != nil || !ok {
			log.Fatal().Str("path", *sslPath).Err(err).Msg("invalid SSL file path")
		} else {
			attachPaths = append(attachPaths, *sslPath)
		}
	}
	if len(attachPaths) == 0 {
		log.Fatal().Msg("no valid libssl path to attach")
	}
	log.Info().Any("path", attachPaths).Msg("using libssl")

	sslObjs := sslObjects{}
	SSLSpec, err := ebpf.LoadCollectionSpec(sslSpecPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load ebpf spec")
	}

	if err := SSLSpec.LoadAndAssign(&sslObjs, nil); err != nil {
		log.Fatal().Err(err).Msg("failed to load and assign ebpf objects")
	}

	for _, p := range attachPaths {
		exec, err := link.OpenExecutable(p)
		if err != nil {
			log.Fatal().Str("path", p).Err(err).Msg("failed to open file")
		} else {
			attachSSLProbes(exec, &sslObjs, p, links)
			log.Info().Str("path", p).Msg("attaching SSL uprobes")
		}
	}

	return &sslObjs
}

func attachRustlsProbes(ex *link.Executable, objs *rustlsObjects, target string, links *[]link.Link) {
	probes := []struct {
		address uint64
		prog    *ebpf.Program
		inject  func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{0x27BFB60, objs.ProbeRustlsTokioPollReadEntry, ex.Uprobe},
		{0x27BFB60, objs.ProbeRustlsTokioPollReadExit, ex.Uretprobe},
		{0x27BFDD0, objs.ProbeRustlsTokioPollWriteEntry, ex.Uprobe},
	}

	failedProbes := 0
	for _, probe := range probes {
		up, err := probe.inject("rustls", probe.prog, &link.UprobeOptions{Address: probe.address})
		if err != nil {
			log.Warn().Str("target", target).Err(err).Msgf("failed to attach rustls probe %d", probe.address)
			failedProbes++
			continue
		}
		*links = append(*links, up)
	}
	if failedProbes > 0 {
		log.Fatal().Int("failed", failedProbes).Str("target", target).Msg("failed to attach rustls")
	}
}

func addRustlsProbe(rustlsPath *string, links *[]link.Link) *rustlsObjects {
	if rustlsPath == nil || len(*rustlsPath) == 0 {
		return nil
	}
	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Str("path", *rustlsPath).Value()
	if ok, err := isFilePath(*rustlsPath); err != nil || !ok {
		logger.Fatal().Err(err).Msg("invalid rustls file path")
	}
	logger.Info().Msg("using rustls")
	rustObjs := rustlsObjects{}
	rustSpec, err := ebpf.LoadCollectionSpec(rustlsSpecPath)
	if err != nil {
		logger.Fatal().Msg("failed to load rustls ebpf spec")
	}
	if err := rustSpec.LoadAndAssign(&rustObjs, nil); err != nil {
		logger.Fatal().Err(err).Msg("failed to load and assign rustls ebpf objects")
	}
	exec, err := link.OpenExecutable(*rustlsPath)
	if err != nil {
		logger.Fatal().Msg("failed to open file")
	} else {
		attachRustlsProbes(exec, &rustObjs, *rustlsPath, links)
		logger.Info().Msg("attaching rustls uprobes")
	}
	return &rustObjs
}

type SSLProbe struct {
	links      []link.Link
	sslObjs    *sslObjects
	rustlsObjs *rustlsObjects
	rbs        []*ringbuf.Reader
	client     *collector.GatewayClient
	reqChan    chan *collector.RawRequest
	respChan   chan *collector.RawResponse
}

func NewSSLProbe(sslPath, rustlsPath *string, client *collector.GatewayClient) *SSLProbe {
	links := []link.Link{}
	sslObjs := addSSLProbe(sslPath, &links)
	rustlsObjs := addRustlsProbe(rustlsPath, &links)

	rbs := []*ringbuf.Reader{}
	sslRingbuffer, err := ringbuf.NewReader(sslObjs.Events)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open ringbuf reader")
	}
	rbs = append(rbs, sslRingbuffer)
	if rustlsObjs != nil {
		rustlsRingBuffer, err := ringbuf.NewReader(rustlsObjs.Events)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to open rustls ringbuf reader")
		}
		rbs = append(rbs, rustlsRingBuffer)
	}

	return &SSLProbe{
		sslObjs:    sslObjs,
		rustlsObjs: rustlsObjs,
		links:      links,
		rbs:        rbs,
		client:     client,
		reqChan:    make(chan *collector.RawRequest, collector.GatewayChannelSize),
		respChan:   make(chan *collector.RawResponse, collector.GatewayChannelSize),
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
	for i, rb := range sp.rbs {
		wg.Go(func() {
			logger := log.DefaultLogger
			logger.Context = log.NewContext(nil).Int("rb_index", i).Value()
			for {
				record, err := rb.Read()
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
						Uint64("*SSL", event.SslPtr).
						Uint64("data_len", event.DataLen).
						Uint8("rw", event.Rw).
						Str("comm", collector.CharsToString(event.Comm[:])).
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
	err := sp.sslObjs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close ssl objects")
	}
	if sp.rustlsObjs != nil {
		err = sp.rustlsObjs.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close rustls objects")
		}
	}
	close(sp.reqChan)
	close(sp.respChan)
	for i, rb := range sp.rbs {
		err = rb.Close()
		if err != nil {
			log.Error().Int("index", i).Err(err).Msg("failed to close ssl ringbuf reader")
		}
	}
	for i, l := range sp.links {
		err = l.Close()
		if err != nil {
			log.Error().Int("index", i).Err(err).Msg("failed to close link")
		}
	}
}
