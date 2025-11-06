package collector

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf/rlimit"
)

func CharsToString(arr []int8) string {
	b := make([]byte, len(arr))
	for i, v := range arr {
		b[i] = byte(v)
	}
	return string(bytes.TrimRight(b, "\x00"))
}

func InitEBPF() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to unlock mem for eBPF: %w", err)
	}
	return nil
}
