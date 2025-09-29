package sslsniff

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/phuslu/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// SSL read/write
	SSL_RW_READ  = 4
	SSL_RW_WRITE = 2

	// HTTP
	HTTP1_DELIMITER_LEN    = 4
	HTTP2_FRAME_HEADER_LEN = 9
	CRLF_LEN               = 2
	SSEHeaderPrefix        = "text/event-stream"
	SSEEndChunkLength      = uint64(len("0")) + 2*CRLF_LEN // "0\r\n\r\n"
)

var (
	// HTTP
	CRLF           = []byte("\r\n")
	HTTP1DELIMITER = []byte("\r\n\r\n")
	HTTP2PREFACE   = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
)

type SSLKey struct {
	PidTgid uint64
	UidGid  uint64
	SslPtr  uint64
}

type EventInfo struct {
	TimestampNs uint64
	DataLen     uint32
	Comm        [16]int8
}

type SSLRecord struct {
	Info        []*EventInfo
	Stream      []uint8
	LastResp    *http.Response
	EndOfStream bool
}

func (r *SSLRecord) Append(data []uint8, info *EventInfo) {
	r.Stream = append(r.Stream, data...)
	r.Info = append(r.Info, info)
}

type SSLStore struct {
	Request     map[SSLKey]*SSLRecord
	Response    map[SSLKey]*SSLRecord
	reqMu       sync.Mutex
	respMu      sync.Mutex
	interval    time.Duration
	http1Parser *HTTP1Parser
	http2Parser *HTTP2Parser
}

func NewSSLStore() *SSLStore {
	return &SSLStore{
		interval:    time.Second,
		Request:     make(map[SSLKey]*SSLRecord),
		Response:    make(map[SSLKey]*SSLRecord),
		http1Parser: &HTTP1Parser{},
		http2Parser: NewHTTP2Parser(),
	}
}

func (s *SSLStore) Add(event *sslEvent) {
	key := SSLKey{
		PidTgid: event.PidTgid,
		UidGid:  event.UidGid,
		SslPtr:  event.SslPtr,
	}
	info := &EventInfo{
		TimestampNs: event.TimestampNs,
		DataLen:     event.DataLen,
		Comm:        event.Comm,
	}
	switch event.Rw {
	case SSL_RW_WRITE:
		s.reqMu.Lock()
		record, ok := s.Request[key]
		if !ok {
			record = &SSLRecord{}
			s.Request[key] = record
		}
		record.Append(event.Data[:event.DataLen], info)
		s.reqMu.Unlock()
	case SSL_RW_READ:
		s.respMu.Lock()
		record, ok := s.Response[key]
		if !ok {
			record = &SSLRecord{}
			s.Response[key] = record
		}
		record.Append(event.Data[:event.DataLen], info)
		s.respMu.Unlock()
	}
}

func (s *SSLStore) parseRequest() {
	s.reqMu.Lock()
	defer s.reqMu.Unlock()

	var parser HTTPParser
	for key, req := range s.Request {
		if len(req.Stream) <= 0 {
			continue
		}
		if isBinary(req.Stream) {
			parser = s.http2Parser
		} else {
			parser = s.http1Parser
		}
		request, consumed, err := parser.ParseRequest(req.Stream)
		if err != nil {
			log.Error().Str("body", string(req.Stream[:consumed])).Err(err).Msg("failed to parse HTTP request")
		} else if consumed == 0 {
			continue
		}
		var timestamp uint64
		var comm string
		if consumed == len(req.Stream) {
			timestamp = req.Info[len(req.Info)-1].TimestampNs
			comm = charsToString(req.Info[len(req.Info)-1].Comm[:])
			delete(s.Request, key)
		} else {
			req.Stream = req.Stream[consumed:]
			index := 0
			length := consumed
			for i, info := range req.Info {
				if length == 0 {
					index = i
					break
				} else if length >= int(info.DataLen) {
					length -= int(info.DataLen)
				} else {
					index = i
					log.Warn().Int("consumed", length).Uint32("data", info.DataLen).Msg("detected parse error")
				}
			}
			if index == 0 {
				log.Warn().Int("consumed", length).Msg("consumed data is less than the first record")
				// set to 1 to skip the first record
				index = 1
			}
			timestamp = req.Info[index-1].TimestampNs
			comm = charsToString(req.Info[index-1].Comm[:])
			// keep the unparsed info
			req.Info = req.Info[index:]
		}
		body, err := readCloserToString(request.Body)
		if err != nil {
			log.Error().Err(err).Msg("failed to read request body")
		}
		log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", request.Header).Int64("content_length", request.ContentLength).Str("url", request.RequestURI).Str("method", request.Method).Str("protocol", request.Proto).Str("body", body).Msg("")
	}
}

func (s *SSLStore) parseResponse() {
	s.respMu.Lock()
	defer s.respMu.Unlock()

	var parser HTTPParser
	for key, resp := range s.Response {
		if len(resp.Stream) <= 0 {
			continue
		}
		if isBinary(resp.Stream) {
			parser = s.http2Parser
		} else {
			parser = s.http1Parser
		}
		response, consumed, err := parser.ParseResponse(resp)
		if err != nil {
			log.Error().Err(err).Msg("failed to parse HTTP response")
		}
		if consumed == 0 {
			continue
		}
		var timestamp uint64
		var comm string
		if consumed == len(resp.Stream) && resp.EndOfStream {
			timestamp = resp.Info[len(resp.Info)-1].TimestampNs
			comm = charsToString(resp.Info[len(resp.Info)-1].Comm[:])
			delete(s.Response, key)
		} else {
			resp.Stream = resp.Stream[consumed:]
			index := 0
			last := 0
			length := consumed
			for i, info := range resp.Info {
				index = i
				if length == 0 {
					break
				} else if length >= int(info.DataLen) {
					length -= int(info.DataLen)
				} else {
					// could be the 1st chunk of SSE
					break
				}
				last = i
				if i == len(resp.Info)-1 && length == 0 {
					// consumed all data
					index = len(resp.Info)
				}
			}
			timestamp = resp.Info[last].TimestampNs
			comm = charsToString(resp.Info[last].Comm[:])
			// keep the unparsed info
			resp.Info = resp.Info[index:]
		}
		body, err := readCloserToString(response.Body)
		if err != nil {
			log.Error().Err(err).Msg("failed to read request body")
		}
		log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", response.Header).Int64("content_length", response.ContentLength).Int("status_code", response.StatusCode).Str("protocol", response.Proto).Str("body", body).Msg("")
	}
}

func (s *SSLStore) Parse(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.parseRequest()
			s.parseResponse()
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

func readCloserToString(rc io.ReadCloser) (string, error) {
	defer func() {
		err := rc.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close ReadCloser")
		}
	}()
	buf, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

type HTTPParser interface {
	ParseRequest(data []uint8) (*http.Request, int, error)
	ParseResponse(record *SSLRecord) (*http.Response, int, error)
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

func parseSSE(data []uint8) (string, uint64, error) {
	if idx := bytes.Index(data, CRLF); idx != -1 {
		length, err := strconv.ParseUint(string(data[:idx]), 16, 64)
		if err != nil {
			return "", 0, fmt.Errorf("failed to parse SSE length: %w", err)
		}
		consumed := uint64(idx) + CRLF_LEN + length + CRLF_LEN
		if consumed > uint64(len(data)) {
			// wait for more data
			return "", 0, nil
		}
		return string(data[idx+CRLF_LEN : idx+CRLF_LEN+int(length)]), consumed, nil
	}
	return "", 0, fmt.Errorf("failed to parse SSE length: no CRLF found")
}

func (h1 *HTTP1Parser) ParseResponse(record *SSLRecord) (*http.Response, int, error) {
	reader := bytes.NewReader(record.Stream)
	br := bufio.NewReader(reader)

	// SSE
	if record.LastResp != nil && strings.HasPrefix(record.LastResp.Header.Get("Content-Type"), SSEHeaderPrefix) {
		sse, consumed, err := parseSSE(record.Stream)
		if err != nil {
			return nil, 0, err
		}
		switch consumed {
		case 0:
			return nil, 0, nil
		case SSEEndChunkLength:
			// end of the SSE stream
			record.EndOfStream = true
		default:
			record.EndOfStream = false
		}
		resp := record.LastResp
		resp.Body = io.NopCloser(bytes.NewReader([]byte(sse)))
		resp.ContentLength = int64(len(sse))
		return resp, int(consumed), nil
	}

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		// should wait for more data if it's unexpected EOF
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, nil
		}
		// trim to the `\r\n\r\n`
		if idx := bytes.Index(record.Stream, HTTP1DELIMITER); idx != -1 {
			return nil, idx + HTTP1_DELIMITER_LEN, err
		}
		// have to throw away to avoid infinite loop
		return nil, 0, err
	}
	// find the end of the header
	idx := bytes.Index(record.Stream, HTTP1DELIMITER)
	if idx == -1 {
		return resp, len(record.Stream), fmt.Errorf("cannot find the end of HTTP header")
	}
	// update the last response
	record.LastResp = resp

	contentLength := resp.ContentLength
	// SSE, leave the body for the next round
	if strings.HasPrefix(resp.Header.Get("Content-Type"), SSEHeaderPrefix) && resp.ContentLength == -1 {
		record.EndOfStream = false
		contentLength = 0
		resp.Body = io.NopCloser(bytes.NewReader([]byte{})) // change to empty body
	} else {
		// Non-Streaming response should end
		record.EndOfStream = true
	}
	return resp, idx + HTTP1_DELIMITER_LEN + int(contentLength), nil
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

	for !end {
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

func (h2 *HTTP2Parser) ParseResponse(record *SSLRecord) (*http.Response, int, error) {
	headers, body, lastPos, err := h2.parse(record.Stream)
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
	record.EndOfStream = true
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
