//go:build amd64 && linux

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/phuslu/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 read read.bpf.c -- -I../headers

const (
	specPath      = "sslsniff/read_x86_bpfel.o"
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

func findLibSSLPath() (string, error) {
	if p := os.Getenv(libSSLPathEnv); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("libssl path from env `%s` does not exist: %s", libSSLPathEnv, p)
	}

	for _, path := range libSSLCandidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	for _, dir := range libSDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "libssl.so*"))
		if len(matches) > 0 {
			log.Info().Str("path", matches[0]).Msg("found potential libssl, consider add this to the env")
			return matches[0], nil
		}
	}
	return "", fmt.Errorf("libssl not found, please set the path via env %s", libSSLPathEnv)
}

func charsToString(arr []int8) string {
	b := make([]byte, len(arr))
	for i, v := range arr {
		b[i] = byte(v)
	}
	return string(bytes.TrimRight(b, "\x00"))
}

func parseHTTPResponse(data []uint8) (*http.Response, error) {
	buf := bytes.NewBuffer(data)
	resp, err := http.ReadResponse(bufio.NewReader(buf), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, nil
}

func main() {
	if log.IsTerminal(os.Stderr.Fd()) {
		log.DefaultLogger = log.Logger{
			TimeFormat: "15:04:05",
			Caller:     1,
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				QuoteString:    true,
				EndWithMessage: true,
			},
		}
	}

	libPath, err := findLibSSLPath()
	if err != nil {
		log.Fatal().Err(err).Msg("cannot find the libssl path")
	}
	log.Info().Str("path", libPath).Msg("using libssl")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	objs := readObjects{}
	spec, err := ebpf.LoadCollectionSpec(specPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load ebpf spec")
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal().Err(err).Msg("failed to load and assign ebpf objects")
	}
	defer objs.Close()

	so, err := link.OpenExecutable(libPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open libssl")
	}

	read, err := so.Uprobe("SSL_read", objs.readPrograms.ProbeSslReadEntry, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to attach uprobe SSL_read")
	}
	defer read.Close()

	readRet, err := so.Uretprobe("SSL_read", objs.readPrograms.ProbeSslReadExit, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to attach uretprobe SSL_read")
	}
	defer readRet.Close()

	readExRet, err := so.Uretprobe("SSL_read_ex", objs.readPrograms.ProbeSslReadExExit, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to attach uretprobe SSL_read_ex")
	}
	defer readExRet.Close()

	writeRet, err := so.Uretprobe("SSL_write", objs.readPrograms.ProbeSslWriteExit, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to attach uprobe SSL_write")
	}
	defer writeRet.Close()

	writeExRet, err := so.Uretprobe("SSL_write_ex", objs.readPrograms.ProbeSslWriteExExit, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to attach uretprobe SSL_write_ex")
	}
	defer writeExRet.Close()

	rb, err := ringbuf.NewReader(objs.readMaps.Events)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open ringbuf reader")
	}
	defer rb.Close()

	go func() {
		<-stopper
		if err := rb.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close ringbuf")
		}
	}()

	log.Info().Msg("listening for SSL read/write events...")

	var event readEvent
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info().Msg("ringbuf closed")
				return
			}
			log.Warn().Err(err).Msg("read from ringbuffer error")
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Error().Err(err).Msg("parsing ringbuf record")
			continue
		}

		log.Info().
			Uint64("timestamp", event.TimestampNs).
			Uint64("req_len", event.ReqLen).
			Uint64("pid_tgid", event.PidTgid).
			Uint64("uid_gid", event.UidGid).
			Uint64("*SSL", event.SslPtr).
			Uint32("data_len", event.DataLen).
			Uint8("rw", event.Rw).
			Str("comm", charsToString(event.Comm[:])).
			Msg("event")

		if event.DataLen < 1024 {
			resp, err := parseHTTPResponse(event.Data[:event.DataLen])
			if err != nil {
				log.Warn().Err(err).Msg("failed to parse response")
			} else {
				resp.Write(os.Stdout)
			}
		}
	}
}
