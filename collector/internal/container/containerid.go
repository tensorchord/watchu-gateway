// Resolves container IDs from cgroup IDs.

package container

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/maypok86/otter/v2"
	"github.com/phuslu/log"
)

const (
	CGROUP_DIR         = "/sys/fs/cgroup"
	REGEX_CONTAINER_ID = `-([0-9a-f]{32,64})\.scope`
)

type ContainerResolver struct {
	cgroupTable *otter.Cache[uint64, string]
	unknown     *otter.Cache[uint64, struct{}]
	re          *regexp.Regexp
	loaderFn    otter.LoaderFunc[uint64, string]
}

func NewContainerResolver() *ContainerResolver {
	cr := ContainerResolver{
		cgroupTable: otter.Must(&otter.Options[uint64, string]{
			ExpiryCalculator: otter.ExpiryAccessing[uint64, string](10 * time.Minute),
		}),
		unknown: otter.Must(&otter.Options[uint64, struct{}]{
			ExpiryCalculator: otter.ExpiryAccessing[uint64, struct{}](10 * time.Minute),
		}),
		re: regexp.MustCompile(REGEX_CONTAINER_ID),
	}
	cr.loaderFn = otter.LoaderFunc[uint64, string](cr.loader)
	return &cr
}

func (cr *ContainerResolver) loader(ctx context.Context, key uint64) (string, error) {
	if _, ok := cr.unknown.GetIfPresent(key); ok {
		return "", otter.ErrNotFound
	}
	renew := make(map[uint64]string)
	if err := filepath.WalkDir(CGROUP_DIR, func(path string, d fs.DirEntry, err error) error {
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
		log.Error().Err(err).Msg("failed to walk the cgroup dir")
		// DO NOT renew the cache
		return "", otter.ErrNotFound
	}
	log.Info().Msg("update the cgroup <-> container table")
	for k, v := range renew {
		cr.cgroupTable.Set(k, v)
	}
	if cid, ok := renew[key]; ok {
		return cid, nil
	}
	cr.unknown.Set(key, struct{}{})
	return "", otter.ErrNotFound
}

func (cr *ContainerResolver) Resolve(ctx context.Context, cgroupID uint64) string {
	if cid, err := cr.cgroupTable.Get(ctx, cgroupID, cr.loaderFn); err == nil {
		return cid
	}
	return fmt.Sprintf("non-container-%d", cgroupID)
}
