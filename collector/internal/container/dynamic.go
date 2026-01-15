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
	ScanInterval   = time.Second * 5
	ProcExeFormat  = "/proc/%s/exe"
	ProcMapsFormat = "/proc/%s/maps"
	RegexLibSSL    = `libssl\.so(\.\d+)*`
)

var (
	PatternLibSSL = regexp.MustCompile(RegexLibSSL)
)

type ContainerLibsDetector struct {
	mu sync.RWMutex
	re *regexp.Regexp
	// <proc:path>
	procLib  map[string]string
	procSkip map[string]struct{}
}

func NewContainerLibsDetector() *ContainerLibsDetector {
	return &ContainerLibsDetector{
		re:       regexp.MustCompile(regexContainerID),
		procLib:  make(map[string]string),
		procSkip: make(map[string]struct{}),
	}
}

func (cld *ContainerLibsDetector) Start(ctx context.Context, ch chan ContainerOpenSSL) {
	ticker := time.NewTicker(ScanInterval)
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
	newProcLib := make(map[string]string)
	newProcSkip := make(map[string]struct{})
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
			if lib, ok := cld.procLib[string(proc)]; ok {
				newProcLib[string(proc)] = lib
				cld.mu.RUnlock()
				continue
			}
			if lib, ok := cld.procSkip[string(proc)]; ok {
				newProcSkip[string(proc)] = lib
				cld.mu.RUnlock()
				continue
			}
			cld.mu.RUnlock()
			path, err := os.Readlink(fmt.Sprintf(ProcExeFormat, proc))
			if err != nil {
				log.Warn().Err(err).Bytes("proc", proc).Msg("failed to readlink")
				continue
			}
			absPath := filepath.Join("/proc", string(proc), "root", path)
			libsslPath, err := findLibSSLInMaps(fmt.Sprintf(ProcMapsFormat, proc))
			if err != nil {
				continue
			}
			if libsslPath == "" {
				// check if the binary has libssl statically linked
				hasOpenSSL, err := findOpenSSLSymbols(absPath)
				if err != nil {
					continue
				}
				if !hasOpenSSL {
					newProcSkip[string(proc)] = struct{}{}
					continue
				}
				libsslPath = absPath
			} else {
				libsslPath = filepath.Join("/proc", string(proc), "root", libsslPath)
			}
			newProcLib[string(proc)] = libsslPath
		}
		return nil
	}); err != nil {
		log.Error().Str("cgroup_dir", cgroupDir).Err(err).Msg("failed to walk the cgroup dir")
		return err
	}
	cld.mu.Lock()
	cld.procLib = newProcLib
	cld.procSkip = newProcSkip
	cld.mu.Unlock()
	return nil
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
		if loc := PatternLibSSL.FindStringIndex(line); len(loc) > 0 {
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
	for _, libPath := range cld.procLib {
		key, err := FindLibKey(libPath)
		if err != nil {
			log.Error().Err(err).Str("lib_path", libPath).Msg("failed to find lib key")
			continue
		}
		res.Libs[*key] = libPath
	}
	return res
}
