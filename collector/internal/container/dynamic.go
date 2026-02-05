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
	SCAN_INTERVAL         = time.Second * 5
	PROC_SKIP_EXPIRE_TIME = time.Minute * 1 // Expire skip entries after 1 minute
	PROC_EXE_FORMAT       = "/proc/%s/exe"
	PROC_MAPS_FORMAT      = "/proc/%s/maps"
	REGEX_LIBSSL          = `libssl\.so(\.\d+)*`
)

var (
	PATTERN_LIBSSL = regexp.MustCompile(REGEX_LIBSSL)
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
	procLib  map[string]string
	procSkip map[string]procSkipEntry
}

func NewContainerLibsDetector(scanHostProc bool) *ContainerLibsDetector {
	return &ContainerLibsDetector{
		re:           regexp.MustCompile(REGEX_CONTAINER_ID),
		scanHostProc: scanHostProc,
		procLib:      make(map[string]string),
		procSkip:     make(map[string]procSkipEntry),
	}
}

func (cld *ContainerLibsDetector) Start(ctx context.Context, ch chan ContainerOpenSSL) {
	ticker := time.NewTicker(SCAN_INTERVAL)
	defer ticker.Stop()

	// Ticker for cleaning up expired skip entries
	cleanupTicker := time.NewTicker(PROC_SKIP_EXPIRE_TIME)
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
		if now.Sub(entry.timestamp) >= PROC_SKIP_EXPIRE_TIME {
			delete(cld.procSkip, proc)
			expiredCount++
		}
	}
	if expiredCount > 0 {
		log.Info().Int("count", expiredCount).Msg("cleaned up expired skip entries")
	}
}

func (cld *ContainerLibsDetector) scan() error {
	newProcLib := make(map[string]string)
	newProcSkip := make(map[string]procSkipEntry)
	if cld.scanHostProc {
		if err := cld.scanHostProcs(newProcLib, newProcSkip); err != nil {
			log.Error().Err(err).Msg("failed to scan host proc")
			return err
		}
	} else {
		if err := cld.scanCgroupProcs(newProcLib, newProcSkip); err != nil {
			log.Error().Str("cgroup_dir", CGROUP_DIR).Err(err).Msg("failed to walk the cgroup dir")
			return err
		}
	}
	cld.mu.Lock()
	cld.procLib = newProcLib
	cld.procSkip = newProcSkip
	cld.mu.Unlock()
	return nil
}

func (cld *ContainerLibsDetector) scanCgroupProcs(newProcLib map[string]string, newProcSkip map[string]procSkipEntry) error {
	return filepath.WalkDir(CGROUP_DIR, func(path string, d fs.DirEntry, err error) error {
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

func (cld *ContainerLibsDetector) scanHostProcs(newProcLib map[string]string, newProcSkip map[string]procSkipEntry) error {
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

func (cld *ContainerLibsDetector) scanProc(proc string, newProcLib map[string]string, newProcSkip map[string]procSkipEntry) {
	cld.mu.RLock()
	if lib, ok := cld.procLib[proc]; ok {
		newProcLib[proc] = lib
		cld.mu.RUnlock()
		return
	}
	// Check if process is in skip cache and if entry hasn't expired
	if skipEntry, ok := cld.procSkip[proc]; ok {
		if time.Since(skipEntry.timestamp) < PROC_SKIP_EXPIRE_TIME {
			// Still valid, keep in skip cache
			newProcSkip[proc] = skipEntry
			cld.mu.RUnlock()
			return
		}
		// Entry expired, will rescan
		log.Debug().Str("proc", proc).Msg("skip entry expired, rescanning process")
	}
	cld.mu.RUnlock()

	path, err := os.Readlink(fmt.Sprintf(PROC_EXE_FORMAT, proc))
	if err != nil {
		log.Debug().Err(err).Str("proc", proc).Msg("failed to readlink")
		return
	}
	absPath := filepath.Join("/proc", proc, "root", path)
	libsslPath, err := findLibSSLInMaps(fmt.Sprintf(PROC_MAPS_FORMAT, proc))
	if err != nil {
		return
	}
	if libsslPath == "" {
		// check if the binary has libssl statically linked
		hasOpenSSL, err := findOpenSSLSymbols(absPath)
		if err != nil {
			return
		}
		if !hasOpenSSL {
			// No SSL found, add to skip cache with current timestamp
			newProcSkip[proc] = procSkipEntry{timestamp: time.Now()}
			log.Debug().Str("proc", proc).Msg("no SSL found, added to skip cache")
			return
		}
		libsslPath = absPath
	} else {
		libsslPath = filepath.Join("/proc", proc, "root", libsslPath)
	}
	log.Info().Str("proc", proc).Str("libssl_path", libsslPath).Msg("found SSL library")
	newProcLib[proc] = libsslPath
}

func findLibSSLInMaps(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if loc := PATTERN_LIBSSL.FindStringIndex(line); len(loc) > 0 {
			fields := bytes.Fields([]byte(line))
			if len(fields) >= 6 {
				return string(fields[5]), nil
			}
		}
	}
	return "", nil
}

func findOpenSSLSymbols(filepath string) (bool, error) {
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
	if len(symbols) == 0 {
		symbols, err = f.DynamicSymbols()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			log.Error().Err(err).Str("file", filepath).Msg("failed to read dynamic symbols")
			return false, err
		}
	}

	for _, sym := range symbols {
		if strings.HasPrefix(sym.Name, "SSL_read") || strings.HasPrefix(sym.Name, "SSL_write") {
			return true, nil
		}
	}
	return false, nil
}

type LibKey struct {
	DeviceID uint64
	INode    uint64
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
	for _, libPath := range cld.procLib {
		fi, err := os.Stat(libPath)
		if err != nil {
			log.Warn().Err(err).Str("path", libPath).Msg("failed to stat libssl path")
			continue
		}
		stat, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			log.Warn().Str("path", libPath).Msg("failed to get stat_t")
			continue
		}
		key := LibKey{
			DeviceID: stat.Dev,
			INode:    stat.Ino,
		}
		res.Libs[key] = libPath
	}
	return res
}
