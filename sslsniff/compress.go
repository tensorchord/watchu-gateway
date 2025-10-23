package sslsniff

import (
	"compress/flate"
	"compress/gzip"
	"io"

	"github.com/phuslu/log"
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
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(body)
	case "deflate":
		reader = flate.NewReader(body)
	default:
		reader = body
	}
	if err != nil {
		return nil, err
	}
	return readCloserToBytes(reader)
}
