package proc

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/phuslu/log"
)

const (
	procExeFormat  = "/proc/%d/exe"
	procMapsFormat = "/proc/%d/maps"
	procRootFormat = "/proc/%d/root/%s"

	// regex
	regexLibSSL = `libssl[0-9a-zA-Z_-]*\.so(\.\d+)*`
)

var (
	patternLibSSL  = regexp.MustCompile(regexLibSSL)
	boringSSLTools = [][]byte{
		[]byte("claude"),
		[]byte("amp"),
		[]byte("opencode"),
	}
)

type TLSLibType int

const (
	TLSLibOpenSSL TLSLibType = iota
	TLSLibBoringSSL
)

type ProcTLSLib struct {
	Path string
	Type TLSLibType
}

func findBoringSSLTools(fields [][]byte) bool {
	for _, field := range fields {
		for _, tool := range boringSSLTools {
			if bytes.Equal(field, tool) {
				return true
			}
		}
	}
	return false
}

func isDefinedTextFunc(sym *elf.Symbol, sections []*elf.Section) bool {
	if sym.Section == elf.SHN_UNDEF {
		return false
	}
	switch elf.ST_BIND(sym.Info) {
	case elf.STB_LOCAL, elf.STB_GLOBAL, elf.STB_WEAK:
	default:
		return false
	}
	symType := elf.ST_TYPE(sym.Info)
	if symType != elf.STT_FUNC && symType != elf.STT_NOTYPE {
		return false
	}
	if int(sym.Section) >= len(sections) {
		return false
	}
	sec := sections[sym.Section]
	if sec == nil {
		return false
	}
	return sec.Flags&elf.SHF_EXECINSTR != 0
}

func findOpenSSLStaticSymbols(filepath string) (bool, error) {
	f, err := elf.Open(filepath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		log.Error().Err(err).Str("file", filepath).Msg("failed to read symbols")
		return false, err
	}

	for _, sym := range symbols {
		if !isDefinedTextFunc(&sym, f.Sections) {
			continue
		}
		if strings.HasPrefix(sym.Name, "SSL_read") || strings.HasPrefix(sym.Name, "SSL_write") {
			return true, nil
		}
	}
	return false, nil
}

func DetectTLSLibType(proc int32) ([]ProcTLSLib, error) {
	path, err := os.Readlink(fmt.Sprintf(procExeFormat, proc))
	if err != nil {
		log.Warn().Err(err).Int32("proc", proc).Msg("failed to find the readlink")
		return nil, err
	}
	absPath := fmt.Sprintf(procRootFormat, proc, path)

	// scan maps file
	mapsFile := fmt.Sprintf(procMapsFormat, proc)
	file, err := os.Open(mapsFile)
	if err != nil {
		log.Warn().Err(err).Int32("proc", proc).Msg("failed to open the maps")
		return nil, err
	}
	defer file.Close()
	var libs []ProcTLSLib
	scanner := bufio.NewScanner(file)
	firstLine := true
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Bytes()
		if firstLine {
			firstLine = false
			fields := bytes.Split(line, []byte("/"))
			if findBoringSSLTools(fields) {
				libs = append(libs, ProcTLSLib{
					Path: absPath,
					Type: TLSLibBoringSSL,
				})
			}
		}
		if patternLibSSL.Match(line) {
			fields := bytes.Fields(line)
			if len(fields) >= 6 {
				path := fmt.Sprintf(procRootFormat, proc, fields[5])
				if _, ok := seen[path]; ok {
					continue
				}
				seen[path] = struct{}{}
				libs = append(libs, ProcTLSLib{
					Path: path,
					Type: TLSLibOpenSSL,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn().Err(err).Int32("proc", proc).Msg("failed to scan the maps")
		return nil, err
	}

	if hasOpenSSL, err := findOpenSSLStaticSymbols(absPath); err == nil && hasOpenSSL {
		libs = append(libs, ProcTLSLib{
			Path: absPath,
			Type: TLSLibOpenSSL,
		})
	}
	return libs, nil
}

type LibKey struct {
	DeviceID uint64
	INode    uint64
}

func FindLibKey(path string) (*LibKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat libssl path: %w", err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("failed to get stat_t for libssl path")
	}
	key := LibKey{
		DeviceID: stat.Dev,
		INode:    stat.Ino,
	}
	return &key, nil
}
