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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/maypok86/otter/v2"
	"github.com/phuslu/log"
)

const (
	cgroupDir                    = "/sys/fs/cgroup"
	cgroupContainerUnknownFormat = "non-container-%d"
	regexContainerID             = `-([0-9a-f]{32,64})\.scope`
	updateInterval               = 5 * time.Second
	updateIntervalOnError        = time.Second
)

var errCgroupIDNotFound = errors.New("cgroup id not found")

type cgroupContainer map[uint64]string

type ContainerResolver struct {
	cgroupTable    atomic.Pointer[cgroupContainer]
	mu             sync.Mutex
	nonContainer   *otter.Cache[uint64, struct{}]
	re             *regexp.Regexp
	nextUpdateTime time.Time
}

func NewContainerResolver() *ContainerResolver {
	ct := make(cgroupContainer)
	cr := ContainerResolver{
		nonContainer: otter.Must(&otter.Options[uint64, struct{}]{
			// cgroup IDs could be reused
			ExpiryCalculator: otter.ExpiryCreating[uint64, struct{}](10 * time.Minute),
		}),
		re:             regexp.MustCompile(regexContainerID),
		nextUpdateTime: time.Now(),
	}
	cr.cgroupTable.Store(&ct)
	return &cr
}

func (cr *ContainerResolver) update(ctx context.Context) cgroupContainer {
	renew := make(cgroupContainer)
	if err := filepath.WalkDir(cgroupDir, func(path string, d fs.DirEntry, err error) error {
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
	ct := cr.cgroupTable.Load()
	cid, exist := (*ct)[key]
	if exist {
		return cid, nil
	}
	if _, ok := cr.nonContainer.GetIfPresent(key); ok {
		return fmt.Sprintf(cgroupContainerUnknownFormat, key), nil
	}
	return "", errCgroupIDNotFound
}

func (cr *ContainerResolver) Resolve(ctx context.Context, cgroupID uint64) string {
	if cid, err := cr.load(cgroupID); err == nil {
		return cid
	}
	cr.mu.Lock()
	// re-check to avoid cache stampede, it's intended to block all the cache miss
	// requests here to avoid inconsistent cache state.
	if cid, exist := (*cr.cgroupTable.Load())[cgroupID]; exist {
		cr.mu.Unlock()
		return cid
	}
	if time.Now().Before(cr.nextUpdateTime) {
		cr.mu.Unlock()
		// Assume it's a non-container cgroup ID but doesn't record this
		return fmt.Sprintf(cgroupContainerUnknownFormat, cgroupID)
	}
	log.Info().Uint64("trigger", cgroupID).Msg("updating the cgroup <=> container table")
	defer cr.mu.Unlock()
	renew := cr.update(ctx)
	now := time.Now()
	if renew != nil {
		cr.cgroupTable.Swap(&renew)
		cr.nextUpdateTime = now.Add(updateInterval)
	} else {
		cr.nextUpdateTime = now.Add(updateIntervalOnError)
	}
	if cid, exist := (*cr.cgroupTable.Load())[cgroupID]; exist {
		return cid
	}
	if renew != nil {
		// only cache the unknown cgroup IDs when update is successful
		cr.nonContainer.Set(cgroupID, struct{}{})
	}
	return fmt.Sprintf(cgroupContainerUnknownFormat, cgroupID)
}
