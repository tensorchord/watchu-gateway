package sslsniff

import (
	"compress/flate"
	"compress/gzip"
	"io"
	"strings"

	"github.com/phuslu/log"
)

const (
	EncodingGZip    = "gzip"
	EncodingDeflate = "deflate"
)

func readCloserToBytes(rc io.ReadCloser) ([]byte, error) {
	defer func() {
		err := rc.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close ReadCloser")
		}
	}()
	buf, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func readDecodeBytes(body io.ReadCloser, encoding string) ([]byte, error) {
	if len(encoding) == 0 {
		return readCloserToBytes(body)
	}
	var reader io.ReadCloser
	var err error
	if strings.Contains(encoding, ",") {
		// this is very rare as most cases won't benefit from multiple compressions
		log.Warn().Str("encoding", encoding).Msg("multiple content-encoding detected, only the last one will be used to decode the body")
	}
	// https://www.rfc-editor.org/rfc/rfc9110.html#name-content-encoding
	// If one or more encodings have been applied to a representation, the sender that
	// applied the encodings MUST generate a Content-Encoding header field that lists
	// the content codings in the order in which they were applied.
	switch {
	case strings.HasSuffix(encoding, EncodingGZip):
		reader, err = gzip.NewReader(body)
	case strings.HasSuffix(encoding, EncodingDeflate):
		reader = flate.NewReader(body)
	default:
		reader = body
	}
	if err != nil {
		return nil, err
	}
	return readCloserToBytes(reader)
}
