package skillsecurity

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type RegistryResolution struct {
	SourceRef   string
	Name        string
	Version     string
	GitURL      string
	DownloadURL string
	SkillName   string
}

type RegistryResolver interface {
	Resolve(ctx context.Context, ref string) (RegistryResolution, error)
}

type SkillsRegistryResolver struct {
	githubBaseURL string
}

func NewSkillsRegistryResolver(githubBaseURL string) *SkillsRegistryResolver {
	githubBaseURL = strings.TrimRight(strings.TrimSpace(githubBaseURL), "/")
	if githubBaseURL == "" {
		githubBaseURL = "https://github.com"
	}
	return &SkillsRegistryResolver{
		githubBaseURL: githubBaseURL,
	}
}

func (r *SkillsRegistryResolver) Resolve(ctx context.Context, ref string) (RegistryResolution, error) {
	_ = ctx
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return RegistryResolution{}, errors.New("registry ref is required")
	}

	if looksLikeURL(ref) || strings.HasPrefix(ref, "git@") {
		return RegistryResolution{}, fmt.Errorf("skills.sh registry requires owner/repo/skill, got URL %q", ref)
	}

	if owner, repo, skill, ok := parseOwnerRepoSkill(ref); ok {
		return RegistryResolution{
			SourceRef: ref,
			GitURL:    fmt.Sprintf("%s/%s/%s", r.githubBaseURL, owner, repo),
			SkillName: skill,
		}, nil
	}

	return RegistryResolution{
		SourceRef: ref,
	}, fmt.Errorf("skills.sh registry requires owner/repo/skill format, got %q", ref)
}

func resolveDirectRef(ref string) RegistryResolution {
	ref = strings.TrimSpace(ref)
	if looksLikeArchive(ref) {
		return RegistryResolution{SourceRef: ref, DownloadURL: ref}
	}
	return RegistryResolution{SourceRef: ref, GitURL: ref}
}

func looksLikeURL(ref string) bool {
	lower := strings.ToLower(strings.TrimSpace(ref))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func looksLikeArchive(ref string) bool {
	lower := strings.ToLower(strings.TrimSpace(ref))
	return strings.HasSuffix(lower, ".zip") ||
		strings.HasSuffix(lower, ".tar") ||
		strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".tgz")
}

func parseOwnerRepo(ref string) (string, string, bool) {
	ref = strings.Trim(ref, "/")
	parts := strings.Split(ref, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	owner := strings.TrimSpace(parts[0])
	repo := strings.TrimSpace(parts[1])
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}

func parseOwnerRepoSkill(ref string) (string, string, string, bool) {
	ref = strings.Trim(ref, "/")
	parts := strings.Split(ref, "/")
	if len(parts) != 3 {
		return "", "", "", false
	}
	owner := strings.TrimSpace(parts[0])
	repo := strings.TrimSpace(parts[1])
	skill := strings.TrimSpace(parts[2])
	if owner == "" || repo == "" || skill == "" {
		return "", "", "", false
	}
	return owner, repo, skill, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
