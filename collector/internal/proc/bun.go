package proc

import (
	"bytes"
	"os"
)

const (
	bunFooterSize   = 24
	bunSentinelSize = 16
)

// \n---- Bun! ----\n
var bunSentinel = []byte{
	0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x20, 0x42, 0x75,
	0x6e, 0x21, 0x20, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
}

func isBunBundlePackage(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	stats, err := file.Stat()
	if err != nil {
		return false, err
	}
	if stats.Size() < bunFooterSize {
		return false, nil
	}
	footerStart := stats.Size() - bunFooterSize
	buffer := make([]byte, bunSentinelSize)
	if _, err := file.ReadAt(buffer, footerStart); err != nil {
		return false, err
	}

	if bytes.Equal(bunSentinel, buffer) {
		return true, nil
	}
	return false, nil
}
