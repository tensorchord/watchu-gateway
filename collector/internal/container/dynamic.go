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
	scanInterval       = time.Second * 5
	procExeFormat      = "/proc/%s/exe"
	procMapsFormat     = "/proc/%s/maps"
	procRootFormat     = "/proc/%s/root/%s"
	regexLibSSL        = `libssl[0-9a-zA-Z_-]*\.so(\.\d+)*`
	procSkipExpireTime = time.Minute * 1
)

var (
	patternLibSSL = regexp.MustCompile(regexLibSSL)
)

type procSkipEntry struct {
	timestamp time.Time
}

type ContainerLibsDetector struct {
	mu sync.RWMutex
	re *regexp.Regexp
	// scanHostProc toggles scanning host /proc directly (non-container processes).
	scanHostProc bool
	// <proc:path>
	procLib  map[string][]string
	procSkip map[string]procSkipEntry
}

func NewContainerLibsDetector(scanHostProc bool) *ContainerLibsDetector {
	return &ContainerLibsDetector{
		re:           regexp.MustCompile(regexContainerID),
		scanHostProc: scanHostProc,
		procLib:      make(map[string][]string),
		procSkip:     make(map[string]procSkipEntry),
	}
}

func (cld *ContainerLibsDetector) Start(ctx context.Context, ch chan ContainerOpenSSL) {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	// Ticker for cleaning up expired skip entries
	cleanupTicker := time.NewTicker(procSkipExpireTime)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := cld.scan(); err != nil {
				log.Error().Err(err).Msg("failed to scan container libs")
			}
			ch <- cld.Export()
		case <-cleanupTicker.C:
			cld.cleanupExpiredSkips()
		case <-ctx.Done():
			log.Info().Msg("stop container libs detector")
			close(ch)
			return
		}
	}
}

func (cld *ContainerLibsDetector) cleanupExpiredSkips() {
	cld.mu.Lock()
	defer cld.mu.Unlock()

	now := time.Now()
	expiredCount := 0
	for proc, entry := range cld.procSkip {
		if now.Sub(entry.timestamp) >= procSkipExpireTime {
			delete(cld.procSkip, proc)
			expiredCount++
		}
	}
	if expiredCount > 0 {
		log.Info().Int("count", expiredCount).Msg("cleaned up expired skip entries")
	}
}

func (cld *ContainerLibsDetector) scan() error {
	log.Info().Msg("scanning for container processes with libssl")
	newProcLib := make(map[string][]string)
	newProcSkip := make(map[string]procSkipEntry)
	if cld.scanHostProc {
		if err := cld.scanHostProcs(newProcLib, newProcSkip); err != nil {
			log.Error().Err(err).Msg("failed to scan host proc")
			return err
		}
	} else {
		if err := cld.scanCgroupProcs(newProcLib, newProcSkip); err != nil {
			log.Error().Str("cgroup_dir", cgroupDir).Err(err).Msg("failed to walk the cgroup dir")
			return err
		}
	}
	cld.mu.Lock()
	cld.procLib = newProcLib
	cld.procSkip = newProcSkip
	cld.mu.Unlock()
	return nil
}

func (cld *ContainerLibsDetector) scanCgroupProcs(newProcLib map[string][]string, newProcSkip map[string]procSkipEntry) error {
	return filepath.WalkDir(cgroupDir, func(path string, d fs.DirEntry, err error) error {
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
			cld.scanProc(string(proc), newProcLib, newProcSkip)
		}
		return nil
	})
}

func (cld *ContainerLibsDetector) scanHostProcs(newProcLib map[string][]string, newProcSkip map[string]procSkipEntry) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if !isNumericPID(pid) {
			continue
		}
		cld.scanProc(pid, newProcLib, newProcSkip)
	}
	return nil
}

func isNumericPID(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func (cld *ContainerLibsDetector) scanProc(proc string, newProcLib map[string][]string, newProcSkip map[string]procSkipEntry) {
	cld.mu.RLock()
	if libs, ok := cld.procLib[proc]; ok {
		newProcLib[proc] = libs
		cld.mu.RUnlock()
		return
	}
	// Check if process is in skip cache and if entry hasn't expired
	if skipEntry, ok := cld.procSkip[proc]; ok {
		if time.Since(skipEntry.timestamp) < procSkipExpireTime {
			// Still valid, keep in skip cache
			newProcSkip[proc] = skipEntry
			cld.mu.RUnlock()
			return
		}
		// Entry expired, will rescan
		log.Debug().Str("proc", proc).Msg("skip entry expired, rescanning process")
	}
	cld.mu.RUnlock()

	path, err := os.Readlink(fmt.Sprintf(procExeFormat, proc))
	if err != nil {
		log.Debug().Err(err).Str("proc", proc).Msg("failed to readlink")
		return
	}
	absPath := filepath.Join("/proc", proc, "root", path)
	libsslPaths, err := findLibSSLInMaps(proc, fmt.Sprintf(procMapsFormat, proc))
	if err != nil {
		return
	}
	if len(libsslPaths) == 0 {
		// check if the binary has libssl statically linked
		hasOpenSSL, err := findOpenSSLStaticSymbols(absPath)
		if err != nil {
			return
		}
		if !hasOpenSSL {
			// No SSL found, add to skip cache with current timestamp
			newProcSkip[proc] = procSkipEntry{timestamp: time.Now()}
			log.Debug().Str("proc", proc).Msg("no SSL found, added to skip cache")
			return
		}
		libsslPaths = []string{absPath}
	}
	log.Info().Str("proc", proc).Any("libssl_paths", libsslPaths).Msg("found SSL library")
	newProcLib[proc] = libsslPaths
}

func findLibSSLInMaps(proc string, filename string) ([]string, error) {
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
				path := fmt.Sprintf(procRootFormat, proc, string(fields[5]))
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
	Libs map[LibKey]string
}

func (cld *ContainerLibsDetector) Export() ContainerOpenSSL {
	cld.mu.RLock()
	defer cld.mu.RUnlock()
	res := ContainerOpenSSL{
		Libs: make(map[LibKey]string),
	}
	for _, libPaths := range cld.procLib {
		for _, libPath := range libPaths {
			key, err := FindLibKey(libPath)
			if err != nil {
				log.Error().Err(err).Str("lib_path", libPath).Msg("failed to find lib key")
				continue
			}
			res.Libs[*key] = libPath
		}
	}
	return res
}
