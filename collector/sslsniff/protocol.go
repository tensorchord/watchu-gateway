package sslsniff

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/phuslu/log"
	"golang.org/x/net/http2"

	"github.com/tensorchord/watchu/collector"
	"github.com/tensorchord/watchu/collector/internal/tool"
)

const (
	// SSL
	SSL_MAX_EVENT_SIZE = 64 * 1024               // 64 KiB
	SSL_MAX_DATA_SIZE  = 64 * SSL_MAX_EVENT_SIZE // 4 MiB
	SSL_RW_READ        = 4
	SSL_RW_WRITE       = 2

	// HTTP
	HTTP1_DELIMITER_LEN    = 4
	HTTP2_FRAME_HEADER_LEN = 9
	HTTP2_FRAME_MAX_CODE   = 0x9
	HTTP2_FLAGS_MASK       = 0x1 | 0x4 | 0x8 | 0x20
	CRLF_LEN               = 2
	ChunkedEncodingValue   = "chunked"
	SSEHeaderPrefix        = "text/event-stream"
	StreamEndChunkLength   = uint64(len("0")) + 2*CRLF_LEN // "0\r\n\r\n"
)

var (
	// HTTP
	CRLF                 = []byte("\r\n")
	HTTP1DELIMITER       = []byte("\r\n\r\n")
	HTTP1CHUNK_END       = []byte("0\r\n\r\n")
	HTTP1RESPONSE_PREFIX = []byte("HTTP/")
	HTTP1REQUEST_METHODS = [][]byte{
		[]byte("GET"),
		[]byte("POST"),
		[]byte("PUT"),
		[]byte("DELETE"),
		[]byte("HEAD"),
		[]byte("OPTIONS"),
		[]byte("PATCH"),
		[]byte("TRACE"),
		[]byte("CONNECT"),
	}
	HTTP2PREFACE     = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	HTTP2PREFACE_LEN = len(HTTP2PREFACE)
	HEADER_API_KEYS  = []string{
		"Authorization",
		"X-API-Key",
		"X-Auth-Token",
		"X-Access-Token",
		"X-Session-Token",
		"Cookie",
	}
	HEADER_TOKEN_SECRET = []byte("tensorchord-watchu-sslsniff-mask-secret-c0ffee")
)

func flattenMaskedHeader(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	m := hmac.New(sha256.New, HEADER_TOKEN_SECRET)
	for k, v := range h {
		value := strings.Join(v, ",")
		for _, apiKey := range HEADER_API_KEYS {
			if strings.Contains(k, apiKey) {
				m.Reset()
				m.Write([]byte(value))
				value = fmt.Sprintf("masked-%s", hex.EncodeToString(m.Sum(nil)))
				break
			}
		}
		flat[k] = value
	}
	return flat
}

func isBinary(data []uint8) bool {
	for _, b := range data {
		if unicode.IsControl(rune(b)) && b != 9 && b != 10 && b != 13 {
			return true
		}
	}
	return false
}

func isHTTP2Protocol(buf []uint8) bool {
	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Str("ctx", "[Protocol]").Value()

	if bytes.HasPrefix(buf, HTTP2PREFACE) {
		logger.Trace().Msg("detect HTTP/2 preface")
		return true
	}
	if bytes.HasPrefix(buf, HTTP1RESPONSE_PREFIX) || bytes.HasPrefix(buf, HTTP1CHUNK_END) {
		logger.Trace().Msg("detect HTTP/1.x response")
		return false
	}
	for _, method := range HTTP1REQUEST_METHODS {
		if bytes.HasPrefix(buf, method) {
			logger.Trace().Str("method", string(method)).Msg("detect HTTP/1.x request method")
			return false
		}
	}
	// HTTP/1.x are text based, unless compression is used
	if !isBinary(buf) {
		logger.Trace().Msg("plain text detected, likely HTTP/1.x")
		return false
	}
	// check if it's chunked encoding
	_, consumed, err := parseStream(buf)
	if err == nil && consumed > 0 {
		logger.Trace().Msg("detect HTTP/1.x chunked encoding")
		return false
	}
	// it's very likely HTTP/2 if no HTTP/1.x signature found
	if len(buf) < HTTP2_FRAME_HEADER_LEN {
		logger.Error().Str("buf", hex.EncodeToString(buf)).Msg("cannot determine the protocol version")
		return false
	}
	// try to parse the frame header according to https://datatracker.ietf.org/doc/html/rfc7540
	length := (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2]))
	frameType := buf[3]
	flags := buf[4]
	streamID := binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1)
	if length > SSL_MAX_DATA_SIZE || frameType > HTTP2_FRAME_MAX_CODE || flags&^HTTP2_FLAGS_MASK != 0 {
		logger.Trace().Uint32("length", length).Uint8("frame", frameType).Uint8("flags", flags).Msg("invalid HTTP/2 frame header")
		return false
	}
	//nolint:staticcheck
	if streamID == 0 && !(frameType == uint8(http2.FrameSettings) || frameType == uint8(http2.FramePing) || frameType == uint8(http2.FrameGoAway) || frameType == uint8(http2.FrameWindowUpdate)) {
		logger.Trace().Uint32("stream_id", streamID).Uint8("frame", frameType).Msg("invalid HTTP/2 stream ID with non-control frame")
		return false
	}

	logger.Trace().Msg("guess HTTP2 by default")
	return true
}

type SSLKey struct {
	PidTgid  uint64
	UidGid   uint64
	SSLPtr   uint64
	CgroupID uint64
}

type EventInfo struct {
	TimestampNs uint64
	DataLen     uint64
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
		PidTgid:  event.PidTgid,
		UidGid:   event.UidGid,
		SSLPtr:   event.SslPtr,
		CgroupID: event.CgroupId,
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

func (s *SSLStore) parseRequest(channel chan *collector.RawRequest) {
	s.reqMu.Lock()
	defer s.reqMu.Unlock()

	var parser ProtocolParser
	for key, record := range s.Request {
		if isHTTP2Protocol(record.Stream) {
			parser = s.http2Parser
		} else {
			parser = s.http1Parser
		}
		if len(record.Stream) == 0 {
			continue
		}
		request, consumed, err := parser.ParseRequest(record)
		if err != nil {
			log.Error().Any("key", &key).Bytes("buf", record.Stream[:consumed]).Err(err).Msg("failed to parse HTTP request")
			delete(s.Request, key)
			continue
		}
		// wait for more data
		if consumed == 0 || !record.EndOfStream {
			continue
		}
		var timestamp uint64
		var comm string
		truncated := false
		if consumed == len(record.Stream) {
			timestamp = record.Info[len(record.Info)-1].TimestampNs
			comm = tool.CharsToString(record.Info[len(record.Info)-1].Comm[:])
			delete(s.Request, key)
		} else {
			if consumed >= SSL_MAX_DATA_SIZE {
				truncated = true
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
			comm = tool.CharsToString(record.Info[last].Comm[:])
			// keep the unparsed info
			record.Info = record.Info[index:]
		}
		if request == nil {
			// could be a GoAwayFrame
			continue
		}
		body, err := readDecodeBytes(request.Body, request.Header.Get("Content-Encoding"))
		if err != nil {
			log.Error().Any("key", &key).Err(err).Msg("failed to read request body")
			continue
		}
		url := request.RequestURI
		if request.URL != nil {
			url = request.URL.String()
		}
		request.Header.Add("Host", request.Host)
		headers := flattenMaskedHeader(request.Header)
		log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", headers).Int64("content_length", request.ContentLength).Str("url", url).Str("method", request.Method).Str("protocol", request.Proto).Bytes("body", body).Bool("truncated", truncated).Msg("")
		record.EndOfStream = false
		record.LastResp = nil
		select {
		case channel <- &collector.RawRequest{
			ElapsedNs:     timestamp,
			PidTid:        key.PidTgid,
			UidGid:        key.UidGid,
			CgroupID:      key.CgroupID,
			Comm:          comm,
			Method:        request.Method,
			URL:           url,
			ContentLength: request.ContentLength,
			Protocol:      request.Proto,
			Headers:       headers,
			Body:          body,
			Truncated:     truncated,
		}:
		default:
			log.Warn().Msg("request channel is full, dropping event")
		}
	}
}

func (s *SSLStore) parseResponse(channel chan *collector.RawResponse) {
	s.respMu.Lock()
	defer s.respMu.Unlock()

	var parser ProtocolParser
	for key, record := range s.Response {
		if isHTTP2Protocol(record.Stream) {
			parser = s.http2Parser
		} else {
			parser = s.http1Parser
		}
		for len(record.Stream) > 0 {
			//nolint:bodyclose // io.NopCloser
			response, consumed, err := parser.ParseResponse(record)
			if err != nil {
				log.Error().Any("key", &key).Bytes("buf", record.Stream[:consumed]).Err(err).Msg("failed to parse HTTP response")
				delete(s.Response, key)
				break
			}
			// wait for more data
			if consumed == 0 {
				break
			}
			var timestamp uint64
			var comm string
			if consumed == len(record.Stream) && record.EndOfStream {
				timestamp = record.Info[len(record.Info)-1].TimestampNs
				comm = tool.CharsToString(record.Info[len(record.Info)-1].Comm[:])
				delete(s.Response, key)
			} else {
				// response won't exceed the max size, see github issue #17
				if consumed > len(record.Stream) {
					log.Error().Any("key", &key).Int("consumed", consumed).Int("stream_len", len(record.Stream)).Bytes("stream", record.Stream).Msg("consumed length exceeds stream length")
					consumed = len(record.Stream)
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
				comm = tool.CharsToString(record.Info[last].Comm[:])
				// keep the unparsed info
				record.Info = record.Info[index:]
			}
			if record.EndOfStream {
				if response == nil {
					log.Warn().Int("consumed", consumed).Err(err).Msg("unexpected nil response")
					break
				}
				body, err := readDecodeBytes(response.Body, response.Header.Get("Content-Encoding"))
				if err != nil {
					log.Error().Any("key", &key).Err(err).Msg("failed to read response body")
					continue
				}
				headers := flattenMaskedHeader(response.Header)
				log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", headers).Int64("content_length", response.ContentLength).Int("status_code", response.StatusCode).Str("protocol", response.Proto).Bytes("body", body).Bool("truncated", false).Msg("")
				record.EndOfStream = false
				record.LastResp = nil
				select {
				case channel <- &collector.RawResponse{
					ElapsedNs:     timestamp,
					PidTid:        key.PidTgid,
					UidGid:        key.UidGid,
					CgroupID:      key.CgroupID,
					Comm:          comm,
					StatusCode:    response.StatusCode,
					ContentLength: response.ContentLength,
					Protocol:      response.Proto,
					Headers:       headers,
					Body:          body,
					Truncated:     false,
				}:
				default:
					log.Warn().Msg("response channel is full, dropping event")
				}
				break
			}
		}
	}
}

func (s *SSLStore) Parse(ctx context.Context, reqChan chan *collector.RawRequest, respChan chan *collector.RawResponse) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.parseRequest(reqChan)
			s.parseResponse(respChan)
		}
	}
}

type ProtocolParser interface {
	ParseRequest(record *SSLRecord) (*http.Request, int, error)
	ParseResponse(record *SSLRecord) (*http.Response, int, error)
}
