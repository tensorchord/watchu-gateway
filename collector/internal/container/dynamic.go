// Find out the dynamic linked libraries inside the container.

package container

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phuslu/log"
)

const (
	scanInterval   = time.Second * 5
	procExeFormat  = "/proc/%s/exe"
	procMapsFormat = "/proc/%s/maps"
	procRootFormat = "/proc/%s/root/%s"
	regexLibSSL    = `libssl[0-9a-zA-Z_-]*\.so(\.\d+)*`
	regexClaude    = `claude/versions/[\d.]+`
)

var (
	patternLibSSL    = regexp.MustCompile(regexLibSSL)
	patternBoringSSL = regexp.MustCompile(regexClaude)
)

type ContainerLibsDetector struct {
	mu sync.RWMutex
	re *regexp.Regexp
	// <proc:[paths]>
	procOpenSSLLib   map[string][]string
	procBoringSSLLib map[string][]string
}

func NewContainerLibsDetector() *ContainerLibsDetector {
	return &ContainerLibsDetector{
		re:               regexp.MustCompile(regexContainerID),
		procOpenSSLLib:   make(map[string][]string),
		procBoringSSLLib: make(map[string][]string),
	}
}

func (cld *ContainerLibsDetector) Start(ctx context.Context, ch chan ContainerOpenSSL) {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := cld.scan(); err != nil {
				log.Error().Err(err).Msg("failed to scan container libs")
			}
			ch <- cld.Export()
		case <-ctx.Done():
			log.Info().Msg("stop container libs detector")
			close(ch)
			return
		}
	}
}

func (cld *ContainerLibsDetector) scan() error {
	newOpenSSLLib := make(map[string][]string)
	newBoringSSLLib := make(map[string][]string)
	if err := filepath.WalkDir(cgroupDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		matches := cld.re.FindStringSubmatch(d.Name())
		if matches == nil {
			return nil
		}
		buf, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			log.Warn().Err(err).Str("container", d.Name()).Msg("failed to read the cgroup procs")
			return nil
		}
		procs := bytes.SplitSeq(buf, []byte("\n"))
		for proc := range procs {
			if len(proc) == 0 {
				continue
			}
			cld.mu.RLock()
			if libs, ok := cld.procOpenSSLLib[string(proc)]; ok {
				newOpenSSLLib[string(proc)] = libs
				cld.mu.RUnlock()
				continue
			}
			if libs, ok := cld.procBoringSSLLib[string(proc)]; ok {
				newBoringSSLLib[string(proc)] = libs
				cld.mu.RUnlock()
				continue
			}
			cld.mu.RUnlock()
			path, err := os.Readlink(fmt.Sprintf(procExeFormat, proc))
			if err != nil {
				log.Warn().Err(err).Bytes("proc", proc).Msg("failed to readlink")
				continue
			}
			libsslPaths, err := findLibSSLInMaps(proc)
			if err != nil {
				continue
			}
			absPath := fmt.Sprintf(procRootFormat, string(proc), path)
			// check if the binary has libssl statically linked
			if len(libsslPaths) == 0 {
				if hasOpenSSL, err := findOpenSSLStaticSymbols(absPath); err == nil && hasOpenSSL {
					libsslPaths = append(libsslPaths, absPath)
				}
			}
			newOpenSSLLib[string(proc)] = libsslPaths
			exist, err := findBoringSSLInMaps(proc)
			if err != nil {
				continue
			}
			boringPaths := []string{}
			if exist {
				boringPaths = append(boringPaths, absPath)
			}
			newBoringSSLLib[string(proc)] = boringPaths
		}
		return nil
	}); err != nil {
		log.Error().Str("cgroup_dir", cgroupDir).Err(err).Msg("failed to walk the cgroup dir")
		return err
	}
	cld.mu.Lock()
	cld.procOpenSSLLib = newOpenSSLLib
	cld.procBoringSSLLib = newBoringSSLLib
	cld.mu.Unlock()
	return nil
}

// for now, it only detect the `claude`
func findBoringSSLInMaps(proc []byte) (bool, error) {
	filename := fmt.Sprintf(procMapsFormat, proc)
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if loc := patternBoringSSL.FindStringIndex(line); len(loc) > 0 {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func findLibSSLInMaps(proc []byte) ([]string, error) {
	filename := fmt.Sprintf(procMapsFormat, proc)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	libs := []string{}
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Text()
		if loc := patternLibSSL.FindStringIndex(line); len(loc) > 0 {
			fields := bytes.Fields([]byte(line))
			if len(fields) >= 6 {
				path := fmt.Sprintf(procRootFormat, proc, fields[5])
				if _, ok := seen[path]; ok {
					continue
				}
				seen[path] = struct{}{}
				libs = append(libs, path)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return libs, nil
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

type ContainerOpenSSL struct {
	OpenSSLLibs   map[LibKey]string
	BoringSSLLibs map[LibKey]string
}

func (cld *ContainerLibsDetector) Export() ContainerOpenSSL {
	cld.mu.RLock()
	defer cld.mu.RUnlock()
	res := ContainerOpenSSL{
		OpenSSLLibs:   make(map[LibKey]string),
		BoringSSLLibs: make(map[LibKey]string),
	}
	for _, libPaths := range cld.procOpenSSLLib {
		for _, libPath := range libPaths {
			key, err := FindLibKey(libPath)
			if err != nil {
				log.Error().Err(err).Str("lib_path", libPath).Msg("failed to find lib key")
				continue
			}
			res.OpenSSLLibs[*key] = libPath
		}
	}
	for _, libPaths := range cld.procBoringSSLLib {
		for _, libPath := range libPaths {
			key, err := FindLibKey(libPath)
			if err != nil {
				log.Error().Err(err).Str("boring_path", libPath).Msg("failed to find lib key")
				continue
			}
			res.BoringSSLLibs[*key] = libPath
		}
	}
	return res
}
