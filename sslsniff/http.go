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
	"sync"
	"time"
	"unicode"

	"github.com/phuslu/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// SSL
	SSL_MAX_DATA_SIZE = 64 * 1024 // 64 KiB
	SSL_RW_READ       = 4
	SSL_RW_WRITE      = 2

	// HTTP
	HTTP1_DELIMITER_LEN    = 4
	HTTP2_FRAME_HEADER_LEN = 9
	CRLF_LEN               = 2
	ChunkedEncodingValue   = "chunked"
	SSEHeaderPrefix        = "text/event-stream"
	StreamEndChunkLength   = uint64(len("0")) + 2*CRLF_LEN // "0\r\n\r\n"
)

var (
	// HTTP
	CRLF             = []byte("\r\n")
	HTTP1DELIMITER   = []byte("\r\n\r\n")
	HTTP2PREFACE     = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	HTTP2PREFACE_LEN = len(HTTP2PREFACE)
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
	for key, record := range s.Request {
		if isBinary(record.Stream) {
			parser = s.http2Parser
		} else {
			parser = s.http1Parser
		}
		for len(record.Stream) > 0 {
			request, consumed, err := parser.ParseRequest(record)
			if err != nil {
				log.Error().Str("body", string(record.Stream[:consumed])).Err(err).Msg("failed to parse HTTP request")
			}
			// wait for more data
			if consumed == 0 {
				break
			}
			var timestamp uint64
			var comm string
			truncated := false
			if consumed == len(record.Stream) && record.EndOfStream {
				timestamp = record.Info[len(record.Info)-1].TimestampNs
				comm = charsToString(record.Info[len(record.Info)-1].Comm[:])
				delete(s.Request, key)
			} else {
				if consumed > SSL_MAX_DATA_SIZE {
					truncated = true
					consumed = SSL_MAX_DATA_SIZE
				}
				record.Stream = record.Stream[consumed:]
				index := 0
				last := 0
				length := consumed
				for i, info := range record.Info {
					index = i
					if length == 0 {
						break
					} else if length >= int(info.DataLen) {
						length -= int(info.DataLen)
					} else {
						break
					}
					last = i
					if i == len(record.Info)-1 && length == 0 {
						// consumed all data
						index = len(record.Info)
					}
				}
				timestamp = record.Info[last].TimestampNs
				comm = charsToString(record.Info[last].Comm[:])
				// keep the unparsed info
				record.Info = record.Info[index:]
			}
			if record.EndOfStream {
				if request == nil {
					log.Warn().Int("consumed", consumed).Err(err).Msg("unexpected nil request")
					break
				}
				body, err := readCloserToString(request.Body)
				if err != nil {
					log.Error().Err(err).Msg("failed to read request body")
				}
				url := request.RequestURI
				if request.URL != nil {
					url = request.URL.String()
				}
				log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", request.Header).Int64("content_length", request.ContentLength).Str("url", url).Str("method", request.Method).Str("protocol", request.Proto).Str("body", body).Bool("truncated", truncated).Msg("")
				record.EndOfStream = false
				record.LastResp = nil
				break
			}
		}
	}
}

func (s *SSLStore) parseResponse() {
	s.respMu.Lock()
	defer s.respMu.Unlock()

	var parser HTTPParser
	for key, record := range s.Response {
		if isBinary(record.Stream) {
			parser = s.http2Parser
		} else {
			parser = s.http1Parser
		}
		for len(record.Stream) > 0 {
			response, consumed, err := parser.ParseResponse(record)
			if err != nil {
				log.Error().Err(err).Msg("failed to parse HTTP response")
			}
			// wait for more data
			if consumed == 0 {
				break
			}
			var timestamp uint64
			var comm string
			truncated := false
			if consumed == len(record.Stream) && record.EndOfStream {
				timestamp = record.Info[len(record.Info)-1].TimestampNs
				comm = charsToString(record.Info[len(record.Info)-1].Comm[:])
				delete(s.Response, key)
			} else {
				if consumed > SSL_MAX_DATA_SIZE {
					truncated = true
					consumed = SSL_MAX_DATA_SIZE
				}
				record.Stream = record.Stream[consumed:]
				index := 0
				last := 0
				length := consumed
				for i, info := range record.Info {
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
					if i == len(record.Info)-1 && length == 0 {
						// consumed all data
						index = len(record.Info)
					}
				}
				timestamp = record.Info[last].TimestampNs
				comm = charsToString(record.Info[last].Comm[:])
				// keep the unparsed info
				record.Info = record.Info[index:]
			}
			if record.EndOfStream {
				if response == nil {
					log.Warn().Int("consumed", consumed).Err(err).Msg("unexpected nil response")
					break
				}
				body, err := readCloserToString(response.Body)
				if err != nil {
					log.Error().Err(err).Msg("failed to read request body")
				}
				log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", response.Header).Int64("content_length", response.ContentLength).Int("status_code", response.StatusCode).Str("protocol", response.Proto).Str("body", body).Bool("truncated", truncated).Msg("")
				record.EndOfStream = false
				record.LastResp = nil
				break
			}
		}
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
	ParseRequest(record *SSLRecord) (*http.Request, int, error)
	ParseResponse(record *SSLRecord) (*http.Response, int, error)
}

type HTTP1Parser struct{}

func (h1 *HTTP1Parser) ParseRequest(record *SSLRecord) (*http.Request, int, error) {
	reader := bytes.NewReader(record.Stream)
	br := bufio.NewReader(reader)
	req, err := http.ReadRequest(br)
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
	// find the end of the body
	idx := bytes.Index(record.Stream, HTTP1DELIMITER)
	if idx == -1 {
		return req, len(record.Stream), fmt.Errorf("cannot find the end of HTTP header")
	}
	// check if the body is fully received
	if req.ContentLength >= 0 && idx+HTTP1_DELIMITER_LEN+int(req.ContentLength) > len(record.Stream) {
		// wait for more data, do not return the half-received request body
		record.EndOfStream = false
		return nil, 0, nil
	}
	record.EndOfStream = true
	return req, idx + HTTP1_DELIMITER_LEN + int(req.ContentLength), nil
}

func parseStream(data []uint8) ([]uint8, uint64, error) {
	if idx := bytes.Index(data, CRLF); idx != -1 {
		length, err := strconv.ParseUint(string(data[:idx]), 16, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse stream length: %w", err)
		}
		consumed := uint64(idx) + CRLF_LEN + length + CRLF_LEN
		if consumed > uint64(len(data)) {
			// wait for more data
			return nil, 0, nil
		}
		return data[idx+CRLF_LEN : idx+CRLF_LEN+int(length)], consumed, nil
	}
	return nil, 0, fmt.Errorf("failed to parse stream length: no CRLF found")
}

func isChunkedEncoding(resp *http.Response) bool {
	encodingLen := len(resp.TransferEncoding)
	return encodingLen > 0 && resp.TransferEncoding[encodingLen-1] == ChunkedEncodingValue
}

func (h1 *HTTP1Parser) ParseResponse(record *SSLRecord) (*http.Response, int, error) {
	// streaming response, handle the chunked transfer encoding
	if record.LastResp != nil && isChunkedEncoding(record.LastResp) {
		stream, consumed, err := parseStream(record.Stream)
		if err != nil || consumed == 0 {
			return nil, 0, err
		}
		switch consumed {
		case StreamEndChunkLength:
			// end of the stream
			record.EndOfStream = true
		default:
			record.EndOfStream = false
			record.LastResp.Body = io.NopCloser(io.MultiReader(record.LastResp.Body, bytes.NewReader(stream)))
		}
		return record.LastResp, int(consumed), nil
	}

	reader := bytes.NewReader(record.Stream)
	br := bufio.NewReader(reader)
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
	// Receiving stream, leave the body for the next round
	if isChunkedEncoding(resp) {
		record.EndOfStream = false
		contentLength = 0
		resp.Body = io.NopCloser(bytes.NewReader([]byte{})) // change to empty body, so next time will handle the chunk
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

func (h2 *HTTP2Parser) parse(record *SSLRecord) (headers []hpack.HeaderField, body bytes.Buffer, lastPos int, err error) {
	data := record.Stream
	if bytes.HasPrefix(record.Stream, HTTP2PREFACE) {
		lastPos += HTTP2PREFACE_LEN
		data = data[HTTP2PREFACE_LEN:]
	}

	reader := bytes.NewReader(data)
	framer := http2.NewFramer(nil, reader)
	var frame http2.Frame

	for !record.EndOfStream {
		frame, err = framer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// wait for more data, suppress the EOF error
				err = nil
				return
			}
			err = fmt.Errorf("failed to read HTTP/2 frame: %w", err)
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
				err = fmt.Errorf("failed to decode HTTP/2 headers: %w", err)
				return
			}
			headers = append(headers, hdrs...)
			if f.StreamEnded() {
				record.EndOfStream = true
			}
		case *http2.ContinuationFrame:
			hdrs, err = h2.dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				err = fmt.Errorf("failed to decode HTTP/2 continuation headers: %w", err)
				return
			}
			headers = append(headers, hdrs...)
			if f.HeadersEnded() {
				record.EndOfStream = true
			}
		case *http2.DataFrame:
			body.Write(f.Data())
			if f.StreamEnded() {
				record.EndOfStream = true
			}
		case *http2.RSTStreamFrame, *http2.GoAwayFrame:
			record.EndOfStream = true
		default:
			// ignore other connection-level frames
			log.Debug().Str("frame", fmt.Sprintf("%T", f)).Msg("ignoring non-header/data frame")
		}
		lastPos += int(frame.Header().Length) + HTTP2_FRAME_HEADER_LEN
	}
	return
}

func (h2 *HTTP2Parser) ParseRequest(record *SSLRecord) (*http.Request, int, error) {
	headers, body, lastPos, err := h2.parse(record)
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
	headers, body, lastPos, err := h2.parse(record)
	if err != nil {
		return nil, lastPos, err
	}

	// create a new Response
	if record.LastResp == nil {
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
		record.LastResp = &http.Response{
			Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
			StatusCode: code,
			Header:     hdrs,
			Proto:      "HTTP/2.0",
			ProtoMajor: 2,
			ProtoMinor: 0,
			Body:       io.NopCloser(&body),
		}
	} else {
		record.LastResp.Body = io.NopCloser(io.MultiReader(record.LastResp.Body, &body))
	}
	return record.LastResp, lastPos, nil
}
