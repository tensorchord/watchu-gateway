// Resolves container IDs from cgroup IDs.

package container

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/maypok86/otter/v2"
	"github.com/phuslu/log"
)

const (
	CgroupDir                    = "/sys/fs/cgroup"
	CgroupContainerUnknownFormat = "non-container-%d"
	RegexContainerID             = `-([0-9a-f]{32,64})\.scope`
)

var errCgroupIDNotFound = errors.New("cgroup id not found")

type ContainerResolver struct {
	cgroupTable map[uint64]string
	mu          sync.RWMutex
	unknown     *otter.Cache[uint64, struct{}]
	re          *regexp.Regexp
}

func NewContainerResolver() *ContainerResolver {
	return &ContainerResolver{
		cgroupTable: make(map[uint64]string),
		unknown: otter.Must(&otter.Options[uint64, struct{}]{
			ExpiryCalculator: otter.ExpiryAccessing[uint64, struct{}](10 * time.Minute),
		}),
		re: regexp.MustCompile(RegexContainerID),
	}
}

func (cr *ContainerResolver) update(ctx context.Context) map[uint64]string {
	renew := make(map[uint64]string)
	if err := filepath.WalkDir(CgroupDir, func(path string, d fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
		if err != nil || !d.IsDir() {
			return nil
		}
		matches := cr.re.FindStringSubmatch(d.Name())
		if matches == nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			log.Error().Err(err).Str("dir", d.Name()).Msg("failed to get dir info")
			return nil
		}
		st := info.Sys().(*syscall.Stat_t)
		renew[st.Ino] = matches[1]
		return nil
	}); err != nil {
		// DO NOT renew the cache on failure
		log.Error().Err(err).Msg("failed to walk through the cgroup dir")
		return nil
	}
	return renew
}

func (cr *ContainerResolver) load(key uint64) (string, error) {
	cr.mu.RLock()
	cid, exist := cr.cgroupTable[key]
	cr.mu.RUnlock()
	if exist {
		return cid, nil
	}
	if _, ok := cr.unknown.GetIfPresent(key); ok {
		return fmt.Sprintf(CgroupContainerUnknownFormat, key), nil
	}
	return "", errCgroupIDNotFound
}

func (cr *ContainerResolver) Resolve(ctx context.Context, cgroupID uint64) string {
	if cid, err := cr.load(cgroupID); err == nil {
		return cid
	}
	cr.mu.Lock()
	// re-check to avoid cache stampede
	if cid, exist := cr.cgroupTable[cgroupID]; exist {
		cr.mu.Unlock()
		return cid
	}
	log.Info().Uint64("trigger", cgroupID).Msg("updating the cgroup <=> container table")
	renew := cr.update(ctx)
	if renew != nil {
		cr.cgroupTable = renew
	}
	cr.mu.Unlock()
	if cid, exist := cr.cgroupTable[cgroupID]; exist {
		return cid
	}
	cr.unknown.Set(cgroupID, struct{}{})
	return fmt.Sprintf(CgroupContainerUnknownFormat, cgroupID)
}
