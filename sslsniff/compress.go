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
		log.Warn().Str("encoding", encoding).Msg("multiple content-encoding detected, only the first one will be used")
	}
	switch {
	case strings.HasPrefix(encoding, EncodingGZip):
		reader, err = gzip.NewReader(body)
	case strings.HasPrefix(encoding, EncodingDeflate):
		reader = flate.NewReader(body)
	default:
		reader = body
	}
	if err != nil {
		return nil, err
	}
	return readCloserToBytes(reader)
}
