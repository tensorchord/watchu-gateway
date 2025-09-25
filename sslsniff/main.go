//go:build amd64 && linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/phuslu/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 ssl ssl.bpf.c -- -I../headers

const (
	specPath      = "sslsniff/ssl_x86_bpfel.o"
	libSSLPathEnv = "LIBSSL_PATH"

	// SSL read/write
	SSL_RW_READ  = 4
	SSL_RW_WRITE = 2

	// HTTP
	HTTP1_DELIMITER_LEN    = 4
	HTTP2_FRAME_HEADER_LEN = 9
)

var (
	// HTTP
	HTTP1DELIMITER = []byte("\r\n\r\n")
	HTTP2PREFACE   = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
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

type SSLKey struct {
	PidTgid uint64
	UidGid  uint64
	SslPtr  uint64
}

type SSLStore struct {
	Request  map[SSLKey][]uint8
	Response map[SSLKey][]uint8
	interval time.Duration
	mu       sync.Mutex
}

func NewSSLStore() *SSLStore {
	return &SSLStore{
		interval: time.Second,
		Request:  make(map[SSLKey][]uint8),
		Response: make(map[SSLKey][]uint8),
	}
}

func (s *SSLStore) Add(event *sslEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := SSLKey{
		PidTgid: event.PidTgid,
		UidGid:  event.UidGid,
		SslPtr:  event.SslPtr,
	}
	switch event.Rw {
	case SSL_RW_READ:
		s.Response[key] = append(s.Response[key], event.Data[:event.DataLen]...)
	case SSL_RW_WRITE:
		s.Request[key] = append(s.Request[key], event.Data[:event.DataLen]...)
	}
}

func (s *SSLStore) Parse(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	h1 := &HTTP1Parser{}
	h2 := NewHTTP2Parser()
	var parser HTTPParser

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			for key, req := range s.Request {
				if len(req) <= 0 {
					continue
				}
				if isBinary(req) {
					parser = h2
				} else {
					parser = h1
				}
				request, consumed, err := parser.ParseRequest(req)
				if err != nil {
					log.Error().Str("body", string(req[:consumed])).Err(err).Msg("failed to parse HTTP request")
				} else {
					log.Info().Str("Method", request.Method).Any("URI", request.URL).Any("Header", request.Header).Any("key", key).Msg("Received HTTP request")
				}
				if consumed == len(req) {
					delete(s.Request, key)
				} else {
					s.Request[key] = req[consumed:]
				}
			}
			for key, resp := range s.Response {
				if len(resp) <= 0 {
					continue
				}
				if isBinary(resp) {
					parser = h2
				} else {
					parser = h1
				}
				response, consumed, err := parser.ParseResponse(resp)
				if err != nil {
					log.Error().Err(err).Msg("failed to parse HTTP request")
				} else {
					log.Info().Any("resp", response).Any("key", key).Msg("Received HTTP response")
				}
				if consumed == len(resp) {
					delete(s.Response, key)
				} else {
					s.Response[key] = resp[consumed:]
				}
			}
			s.mu.Unlock()
		}
	}
}

func isBinary(data []uint8) bool {
	for _, b := range data {
		if unicode.IsControl(rune(b)) && b != 9 && b != 10 && b != 13 {
			return true
		}
	}
	return false
}

func NthIndex(s, sub []byte, n int) int {
	if n <= 0 {
		return -1
	}
	start := 0
	for range n {
		idx := bytes.Index(s[start:], sub)
		if idx == -1 {
			return -1
		}
		start += idx + len(sub)
	}
	return start - len(sub)
}

type HTTPParser interface {
	ParseRequest(data []uint8) (*http.Request, int, error)
	ParseResponse(data []uint8) (*http.Response, int, error)
}

type HTTP1Parser struct{}

func (h1 *HTTP1Parser) ParseRequest(data []uint8) (*http.Request, int, error) {
	reader := bytes.NewReader(data)
	br := bufio.NewReader(reader)
	req, err := http.ReadRequest(br)
	if err != nil {
		// should wait for more data if it's unexpected EOF
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, nil
		}
		// trim to the `\r\n\r\n`
		if idx := bytes.Index(data, HTTP1DELIMITER); idx != -1 {
			return nil, idx + HTTP1_DELIMITER_LEN, err
		}
		// have to throw away to avoid infinite loop
		return nil, 0, err
	}
	// find the end of the body
	idx := bytes.Index(data, HTTP1DELIMITER)
	if idx == -1 {
		return req, len(data), fmt.Errorf("cannot find the end of HTTP header")
	}
	return req, idx + HTTP1_DELIMITER_LEN + int(req.ContentLength), nil
}

func (h1 *HTTP1Parser) ParseResponse(data []uint8) (*http.Response, int, error) {
	reader := bytes.NewReader(data)
	br := bufio.NewReader(reader)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		// should wait for more data if it's unexpected EOF
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, nil
		}
		// trim to the `\r\n\r\n`
		if idx := bytes.Index(data, HTTP1DELIMITER); idx != -1 {
			return nil, idx + HTTP1_DELIMITER_LEN, err
		}
		// have to throw away to avoid infinite loop
		return nil, 0, err
	}
	// find the end of the body
	idx := bytes.Index(data, HTTP1DELIMITER)
	if idx == -1 {
		return resp, len(data), fmt.Errorf("cannot find the end of HTTP header")
	}
	return resp, idx + HTTP1_DELIMITER_LEN + int(resp.ContentLength), nil
}

type StreamState struct {
	Headers http2.HeadersFrame
	Body    []byte
	End     bool
}

type HTTP2Parser struct {
	dec *hpack.Decoder
}

func NewHTTP2Parser() *HTTP2Parser {
	return &HTTP2Parser{
		dec: hpack.NewDecoder(4096, nil),
	}
}

func (h2 *HTTP2Parser) parse(data []uint8) (headers []hpack.HeaderField, body bytes.Buffer, lastPos int, err error) {
	if bytes.HasPrefix(data, HTTP2PREFACE) {
		lastPos += len(HTTP2PREFACE)
		data = data[len(HTTP2PREFACE):]
	}
	if len(data) < HTTP2_FRAME_HEADER_LEN {
		return
	}

	reader := bytes.NewReader(data)
	framer := http2.NewFramer(nil, reader)
	end := false
	var frame http2.Frame

	for {
		if end {
			break
		}
		frame, err = framer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// wait for more data
				err = nil
				return
			}
			return
		}
		if frame.Header().StreamID == 0 {
			// ignore connection-level frames
			lastPos += int(frame.Header().Length) + HTTP2_FRAME_HEADER_LEN
			continue
		}
		var hdrs []hpack.HeaderField
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			hdrs, err = h2.dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return
			}
			headers = append(headers, hdrs...)
			if f.StreamEnded() {
				end = true
			}
		case *http2.ContinuationFrame:
			hdrs, err = h2.dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return
			}
			headers = append(headers, hdrs...)
			if f.HeadersEnded() {
				end = true
			}
		case *http2.DataFrame:
			body.Write(f.Data())
			if f.StreamEnded() {
				end = true
			}
		default:
			// ignore other connection-level frames
			log.Debug().Str("frame", fmt.Sprintf("%T", f)).Msg("ignoring non-header/data frame")
		}
		lastPos += int(frame.Header().Length) + HTTP2_FRAME_HEADER_LEN
	}
	return
}

func (h2 *HTTP2Parser) ParseRequest(data []uint8) (*http.Request, int, error) {
	headers, body, lastPos, err := h2.parse(data)
	if err != nil {
		return nil, lastPos, err
	}

	// convert headers to http.Request
	hdrs := http.Header{}
	var method, scheme, path, authority string
	for _, hf := range headers {
		switch hf.Name {
		case ":method":
			method = hf.Value
		case ":scheme":
			scheme = hf.Value
		case ":path":
			path = hf.Value
		case ":authority":
			authority = hf.Value
		default:
			hdrs.Add(hf.Name, hf.Value)
		}
	}
	url := &url.URL{
		Scheme: scheme,
		Host:   authority,
		Path:   path,
	}
	req := &http.Request{
		Method:     method,
		URL:        url,
		Header:     hdrs,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Body:       io.NopCloser(&body),
	}
	return req, lastPos, nil
}

func (h2 *HTTP2Parser) ParseResponse(data []uint8) (*http.Response, int, error) {
	headers, body, lastPos, err := h2.parse(data)
	if err != nil {
		return nil, lastPos, err
	}

	// convert headers to http.Response
	hdrs := http.Header{}
	var code int
	for _, hf := range headers {
		switch hf.Name {
		case ":status":
			code, err = strconv.Atoi(hf.Value)
			if err != nil {
				return nil, lastPos, fmt.Errorf("invalid status code: %s", hf.Value)
			}
		default:
			hdrs.Add(hf.Name, hf.Value)
		}
	}
	if code == 0 {
		return nil, lastPos, fmt.Errorf("missing status code")
	}
	resp := &http.Response{
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode: code,
		Header:     hdrs,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Body:       io.NopCloser(&body),
	}
	return resp, lastPos, nil
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

func attachSSLProbes(ex *link.Executable, objs *sslObjects, target string, links *[]link.Link) {
	if l, err := ex.Uprobe("SSL_read", objs.sslPrograms.ProbeSslReadEntry, nil); err != nil {
		log.Warn().Str("target", target).Err(err).Msg("failed to attach uprobe SSL_read")
	} else {
		*links = append(*links, l)
	}
	if l, err := ex.Uretprobe("SSL_read", objs.sslPrograms.ProbeSslReadExit, nil); err != nil {
		log.Warn().Str("target", target).Err(err).Msg("failed to attach uretprobe SSL_read")
	} else {
		*links = append(*links, l)
	}
	if l, err := ex.Uretprobe("SSL_read_ex", objs.sslPrograms.ProbeSslReadExExit, nil); err != nil {
		log.Warn().Str("target", target).Err(err).Msg("failed to attach uretprobe SSL_read_ex")
	} else {
		*links = append(*links, l)
	}
	if l, err := ex.Uprobe("SSL_write", objs.sslPrograms.ProbeSslWriteEntry, nil); err != nil {
		log.Warn().Str("target", target).Err(err).Msg("failed to attach uprobe SSL_write")
	} else {
		*links = append(*links, l)
	}
	if l, err := ex.Uprobe("SSL_write_ex", objs.sslPrograms.ProbeSslWriteExEntry, nil); err != nil {
		log.Warn().Str("target", target).Err(err).Msg("failed to attach uprobe SSL_write_ex")
	} else {
		*links = append(*links, l)
	}
}

func main() {
	binaryPath := flag.String("binary-path", "", "extra user binary path to attach SSL uprobes (optional)")
	flag.Parse()

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

	attachPaths := []string{libPath}
	if *binaryPath != "" {
		if st, err := os.Stat(*binaryPath); err != nil || st.IsDir() {
			if err != nil {
				log.Warn().Str("binary", *binaryPath).Err(err).Msg("binary not found, skip attaching")
			} else {
				log.Warn().Str("binary", *binaryPath).Msg("path is a directory, skip attaching")
			}
		} else {
			attachPaths = append(attachPaths, *binaryPath)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	objs := sslObjects{}
	spec, err := ebpf.LoadCollectionSpec(specPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load ebpf spec")
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal().Err(err).Msg("failed to load and assign ebpf objects")
	}
	defer objs.Close()

	links := []link.Link{}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	for _, p := range attachPaths {
		exec, err := link.OpenExecutable(p)
		if err != nil {
			log.Fatal().Str("path", p).Err(err).Msg("failed to open file")
		} else {
			log.Info().Str("path", p).Msg("attaching additional SSL uprobes")
			attachSSLProbes(exec, &objs, p, &links)
		}
	}

	rb, err := ringbuf.NewReader(objs.sslMaps.Events)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open ringbuf reader")
	}
	defer rb.Close()

	go func() {
		<-ctx.Done()
		if err := rb.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close ringbuf")
		}
	}()

	log.Info().Msg("listening for SSL read/write events...")

	var event sslEvent
	store := NewSSLStore()
	go store.Parse(ctx)
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

		store.Add(&event)
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

		if isBinary(event.Data[:event.DataLen]) {
			log.Debug().Str("data", string(hex.EncodeToString(event.Data[:event.DataLen]))).Msg("HTTP/2")
		} else {
			log.Debug().Str("data", string(event.Data[:event.DataLen])).Msg("HTTP/1")
		}
	}
}
