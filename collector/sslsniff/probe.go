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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ssl ssl.bpf.c -- -I../headers

const (
	specPath      = "sslsniff/ssl_x86_bpfel.o"
	libSSLPathEnv = "LIBSSL_PATH"
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
	return "", fmt.Errorf("libssl not found, please set the path via env %s", libSSLPathEnv)
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

type SSLProbe struct {
	links    []link.Link
	objs     *sslObjects
	rb       *ringbuf.Reader
	client   *collector.GatewayClient
	reqChan  chan *collector.RawRequest
	respChan chan *collector.RawResponse
}

func NewSSLProbe(additionalFile *string, client *collector.GatewayClient) *SSLProbe {
	attachPaths := []string{}
	libPath, err := findLibSSLPath()
	if err != nil {
		log.Warn().Err(err).Msg("cannot find the libssl path")
	} else {
		attachPaths = append(attachPaths, libPath)
	}

	if additionalFile != nil && len(*additionalFile) > 0 {
		if ok, err := isFilePath(*additionalFile); err != nil || !ok {
			log.Fatal().Str("path", *additionalFile).Err(err).Msg("invalid additional binary path")
		} else {
			attachPaths = append(attachPaths, *additionalFile)
		}
	}
	if len(attachPaths) == 0 {
		log.Fatal().Msg("no valid libssl or additional binary path to attach")
	}
	log.Info().Any("path", attachPaths).Msg("using libssl")

	objs := sslObjects{}
	spec, err := ebpf.LoadCollectionSpec(specPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load ebpf spec")
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal().Err(err).Msg("failed to load and assign ebpf objects")
	}

	links := []link.Link{}
	for _, p := range attachPaths {
		exec, err := link.OpenExecutable(p)
		if err != nil {
			log.Fatal().Str("path", p).Err(err).Msg("failed to open file")
		} else {
			attachSSLProbes(exec, &objs, p, &links)
			log.Info().Str("path", p).Msg("attaching SSL uprobes")
		}
	}

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open ringbuf reader")
	}

	return &SSLProbe{
		objs:     &objs,
		links:    links,
		rb:       rb,
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
	for {
		record, err := sp.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("SSL ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("read from ringbuffer error")
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("parsing ssl ringbuf record")
			continue
		}

		store.Add(&event)
		if log.Debug().Enabled() {
			var data, protocol string
			if isHTTP2Protocol(event.Data[:event.DataLen]) {
				data = hex.EncodeToString(event.Data[:event.DataLen])
				protocol = "HTTP/2"
			} else {
				data = string(event.Data[:event.DataLen])
				protocol = "HTTP/1"
			}
			log.Debug().
				Uint64("timestamp", event.TimestampNs).
				Uint64("req_len", event.ReqLen).
				Uint64("pid_tgid", event.PidTgid).
				Uint64("uid_gid", event.UidGid).
				Uint64("*SSL", event.SslPtr).
				Uint32("data_len", event.DataLen).
				Uint8("rw", event.Rw).
				Str("comm", collector.CharsToString(event.Comm[:])).
				Str("data", data).
				Str("protocol", protocol).
				Msg("HTTP event")
		}
	}
}

func (sp *SSLProbe) Close() {
	err := sp.objs.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close ssl objects")
	}
	close(sp.reqChan)
	close(sp.respChan)
	err = sp.rb.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close ssl ringbuf reader")
	}
	for i, l := range sp.links {
		err = l.Close()
		if err != nil {
			log.Error().Int("index", i).Err(err).Msg("failed to close link")
		}
	}
}
