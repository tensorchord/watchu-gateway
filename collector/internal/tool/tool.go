package tool

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/phuslu/log"
)

func CharsToString(arr []int8) string {
	b := make([]byte, len(arr))
	for i, v := range arr {
		if v == 0 {
			break
		}
		b[i] = byte(v)
	}
	return string(bytes.TrimRight(b, "\x00"))
}

func ReadCloserToBytes(rc io.ReadCloser) ([]byte, error) {
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

func IsFilePath(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return !st.IsDir(), nil
}

func InitEBPF() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to unlock mem for eBPF: %w", err)
	}
	return nil
}
