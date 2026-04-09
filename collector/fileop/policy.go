//go:build amd64 && linux

package fileop

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/tensorchord/watchu/collector/export"
)

//go:embed default-policy.toml
var defaultPolicyBytes []byte

type Policy struct {
	ReadPrefixes     []string `json:"read_prefixes" toml:"read_prefixes"`
	ReadHomePrefixes []string `json:"read_home_prefixes" toml:"read_home_prefixes"`
	ReadSuffixes     []string `json:"read_suffixes" toml:"read_suffixes"`

	WritePrefixes     []string `json:"write_prefixes" toml:"write_prefixes"`
	WriteHomePrefixes []string `json:"write_home_prefixes" toml:"write_home_prefixes"`
	WriteSuffixes     []string `json:"write_suffixes" toml:"write_suffixes"`
}

func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		return loadPolicyBytes(defaultPolicyBytes, ".toml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fileop policy %s: %w", path, err)
	}

	policy, err := loadPolicyBytes(data, filepath.Ext(path))
	if err != nil {
		return nil, fmt.Errorf("parse fileop policy %s: %w", path, err)
	}
	return policy, nil
}

func loadPolicyBytes(data []byte, ext string) (*Policy, error) {
	var policy Policy

	switch strings.ToLower(ext) {
	case ".json":
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, err
		}
	case ".toml", "":
		if err := toml.Unmarshal(data, &policy); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported fileop policy format %q", ext)
	}
	policy.normalize()
	return &policy, nil
}

func (p Policy) Matches(raw *export.RawFileOp) bool {
	switch raw.Op {
	case "open":
		return p.matchesOpen(raw)
	case "write", "mmap_write":
		return p.matchesWritePath(raw.Path)
	case "delete":
		return p.matchesWritePath(raw.Path)
	case "rename":
		return p.matchesWritePath(raw.Path) || p.matchesWritePath(raw.NewPath)
	default:
		return false
	}
}

func (p Policy) matchesOpen(raw *export.RawFileOp) bool {
	switch raw.Access {
	case "read":
		return p.matchesReadPath(raw.Path)
	case "write", "read_write":
		return p.matchesWritePath(raw.Path)
	default:
		return false
	}
}

func (p Policy) matchesReadPath(path string) bool {
	return matchPath(path, p.ReadPrefixes, p.ReadHomePrefixes, p.ReadSuffixes)
}

func (p Policy) matchesWritePath(path string) bool {
	return matchPath(path, p.WritePrefixes, p.WriteHomePrefixes, p.WriteSuffixes)
}

func matchPath(path string, prefixes []string, homePrefixes []string, suffixes []string) bool {
	if matchesAnyPrefix(path, prefixes) || matchesAnySuffix(path, suffixes) {
		return true
	}

	homePath, ok := homeScopedPath(path)
	if !ok {
		return false
	}

	return matchesAnyPrefix(homePath, homePrefixes)
}

func homeScopedPath(path string) (string, bool) {
	if path == "/root" {
		return "", false
	}
	if rest, ok := strings.CutPrefix(path, "/root/"); ok {
		return normalizeHomeScopedPath(rest)
	}

	rest, ok := strings.CutPrefix(path, "/home/")
	if !ok {
		return "", false
	}
	_, suffix, ok := strings.Cut(rest, "/")
	if !ok {
		return "", false
	}
	return normalizeHomeScopedPath(suffix)
}

func normalizeHomeScopedPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "", false
	}
	return path, true
}

func (p *Policy) normalize() {
	p.ReadHomePrefixes = normalizeHomePrefixes(p.ReadHomePrefixes)
	p.WriteHomePrefixes = normalizeHomePrefixes(p.WriteHomePrefixes)
}

func normalizeHomePrefixes(prefixes []string) []string {
	for i, prefix := range prefixes {
		prefixes[i] = strings.TrimPrefix(prefix, "/")
	}
	return prefixes
}

func matchesAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func matchesAnySuffix(path string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
