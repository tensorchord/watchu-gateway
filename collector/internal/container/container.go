package container

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"

	"github.com/phuslu/log"
)

const (
	CGROUP_DIR         = "/sys/fs/cgroup"
	CONTAINER_ID_REGEX = `-([0-9a-f]{32,64})\.scope`
)

var (
	ErrCgroupIDNotFound     = errors.New("cgroup id not found")
	ErrCgroupNotInContainer = errors.New("cgroup id not in container")
)

type ContainerResolver struct {
	mu      sync.RWMutex
	cache   map[uint64]string
	unknown map[uint64]struct{}
	re      *regexp.Regexp
}

func NewContainerResolver() *ContainerResolver {
	return &ContainerResolver{
		cache:   make(map[uint64]string),
		unknown: make(map[uint64]struct{}),
		re:      regexp.MustCompile(CONTAINER_ID_REGEX),
	}
}

func (cr *ContainerResolver) update() {
	log.Debug().Msg("renew the cgroup <=> container table")
	renew := make(map[uint64]string)
	if err := filepath.WalkDir(CGROUP_DIR, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		matches := cr.re.FindStringSubmatch(d.Name())
		if matches == nil {
			return nil
		}
		info, _ := d.Info()
		st := info.Sys().(*syscall.Stat_t)
		renew[st.Ino] = matches[1]
		return nil
	}); err != nil {
		log.Error().Err(err).Msg("failed to walk the cgroup dir")
		// DO NOT renew the cache
		return
	}
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.cache = renew
}

func (cr *ContainerResolver) load(cgroupID uint64) (string, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	cid, ok := cr.cache[cgroupID]
	if ok {
		return cid, nil
	}
	_, ok = cr.unknown[cgroupID]
	if ok {
		return "", ErrCgroupNotInContainer
	}
	return "", ErrCgroupIDNotFound
}

func (cr *ContainerResolver) Resolve(cgroupID uint64) string {
	if cid, err := cr.load(cgroupID); err == nil {
		return cid
	} else if errors.Is(err, ErrCgroupNotInContainer) {
		return fmt.Sprintf("non-container-%d", cgroupID)
	}
	cr.update()
	if cid, err := cr.load(cgroupID); err == nil {
		return cid
	}
	cr.mu.Lock()
	cr.unknown[cgroupID] = struct{}{}
	cr.mu.Unlock()
	return fmt.Sprintf("non-container-%d", cgroupID)
}
