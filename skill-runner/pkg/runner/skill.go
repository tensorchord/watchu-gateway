package runner

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// resolveArtifactPath resolves an artifact path to a directory.
// If the path is a directory, it returns it as-is.
// If the path is an archive file (.zip, .tar.gz, .tgz, .tar), it extracts it and returns the extracted directory.
func resolveArtifactPath(path string) (string, func(), error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", nil, err
	}
	if info.IsDir() {
		return path, nil, nil
	}
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractZip(path)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".tar"):
		return extractTar(path)
	default:
		return filepath.Dir(path), nil, nil
	}
}

// extractZip extracts a zip file to a temporary directory and returns the path to the extracted directory.
func extractZip(path string) (string, func(), error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return "", nil, err
	}
	defer reader.Close()

	dest, err := os.MkdirTemp("", "skill-runner-zip-")
	if err != nil {
		return "", nil, err
	}

	// List all files in zip for debugging
	var zipFiles []string
	for _, file := range reader.File {
		zipFiles = append(zipFiles, file.Name)
	}

	for _, file := range reader.File {
		target, err := safeJoin(dest, file.Name)
		if err != nil {
			_ = os.RemoveAll(dest)
			return "", nil, err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				_ = os.RemoveAll(dest)
				return "", nil, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			_ = os.RemoveAll(dest)
			return "", nil, err
		}
		in, err := file.Open()
		if err != nil {
			_ = os.RemoveAll(dest)
			return "", nil, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			in.Close()
			_ = os.RemoveAll(dest)
			return "", nil, err
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			_ = os.RemoveAll(dest)
			return "", nil, err
		}
		in.Close()
		out.Close()
	}

	root := pickSkillRoot(dest)

	// Debug: log what we found
	slog.Default().Info("extractZip completed",
		"zip_path", path,
		"extract_dest", dest,
		"picked_root", root,
		"zip_files", fmt.Sprintf("%v", zipFiles))

	return root, func() { _ = os.RemoveAll(dest) }, nil
}

// extractTar extracts a tar file (optionally gzip-compressed) to a temporary directory.
func extractTar(path string) (string, func(), error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	var reader io.Reader = file
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return "", nil, err
		}
		defer gz.Close()
		reader = gz
	}

	dest, err := os.MkdirTemp("", "skill-runner-tar-")
	if err != nil {
		return "", nil, err
	}

	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = os.RemoveAll(dest)
			return "", nil, err
		}
		if header == nil {
			continue
		}
		target, err := safeJoin(dest, header.Name)
		if err != nil {
			_ = os.RemoveAll(dest)
			return "", nil, err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				_ = os.RemoveAll(dest)
				return "", nil, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				_ = os.RemoveAll(dest)
				return "", nil, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, header.FileInfo().Mode())
			if err != nil {
				_ = os.RemoveAll(dest)
				return "", nil, err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				_ = os.RemoveAll(dest)
				return "", nil, err
			}
			out.Close()
		}
	}

	root := pickSkillRoot(dest)
	return root, func() { _ = os.RemoveAll(dest) }, nil
}

// safeJoin safely joins a base path with a name, preventing directory traversal.
func safeJoin(base, name string) (string, error) {
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("invalid archive path: %s", name)
	}
	target := filepath.Join(base, clean)
	baseClean := filepath.Clean(base) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), baseClean) {
		return "", fmt.Errorf("invalid archive path: %s", name)
	}
	return target, nil
}

// pickSkillRoot picks the skill root directory from an extracted archive.
func pickSkillRoot(dest string) string {
	entries, err := os.ReadDir(dest)
	if err != nil {
		return dest
	}

	// If only one directory entry, return it (common case for single-skill zips)
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(dest, entries[0].Name())
	}

	// Multiple entries: look for a directory containing SKILL.md
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirPath := filepath.Join(dest, entry.Name())
		if findSkillMarkdownPath(dirPath) != "" {
			return dirPath
		}
	}

	// Check if dest itself has SKILL.md (flat zip structure)
	if findSkillMarkdownPath(dest) != "" {
		return dest
	}

	// Fallback: return dest
	return dest
}

// locateSkillDir locates a skill directory within a base directory.
// If skillName is empty, it auto-selects the first skill found.
func locateSkillDir(baseDir, skillName string) (string, error) {
	baseDir = strings.TrimSpace(baseDir)
	skillName = strings.TrimSpace(skillName)

	// Debug: list directory contents
	entries, _ := os.ReadDir(baseDir)
	var entryNames []string
	for _, e := range entries {
		entryNames = append(entryNames, e.Name())
	}

	if baseDir == "" {
		return "", fmt.Errorf("skill base directory is empty")
	}
	if skillName == "" {
		// Try root first (single-skill repo with SKILL.md at root)
		rootHasSkill := hasSkillMarkdown(baseDir)
		slog.Default().Info("locateSkillDir: checking root",
			"baseDir", baseDir,
			"has_SKILL.md", rootHasSkill,
			"entries", fmt.Sprintf("%v", entryNames))

		if rootHasSkill {
			return baseDir, nil
		}
		// Fallback: find first skill in skills/ (multi-skill repo)
		skillsDir := filepath.Join(baseDir, "skills")
		entries, err := os.ReadDir(skillsDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				dirPath := filepath.Join(skillsDir, entry.Name())
				if hasSkillMarkdown(dirPath) {
					return dirPath, nil // Return first skill found
				}
			}
		}
		// No skill found anywhere
		return "", fmt.Errorf("no skill found in repository")
	}

	// Try direct path matches first (for backward compatibility and single-skill repos)
	candidates := []string{
		filepath.Join(baseDir, "skills", skillName),
		filepath.Join(baseDir, skillName),
	}
	if filepath.Base(baseDir) == skillName {
		candidates = append(candidates, baseDir)
	}

	for _, candidate := range candidates {
		if hasSkillMarkdown(candidate) {
			return candidate, nil
		}
	}

	// Fallback: iterate through skills/ directory and match by SKILL.md name field
	skillsDir := filepath.Join(baseDir, "skills")
	skillsEntries, err := os.ReadDir(skillsDir)
	if err == nil {
		for _, entry := range skillsEntries {
			if !entry.IsDir() {
				continue
			}
			dirPath := filepath.Join(skillsDir, entry.Name())
			if !hasSkillMarkdown(dirPath) {
				continue
			}
			nameInMarkdown, err := extractSkillNameFromMarkdown(dirPath)
			if err == nil && nameInMarkdown == skillName {
				return dirPath, nil
			}
		}
	}

	return "", fmt.Errorf("skill %q not found; expected SKILL.md under %s", skillName, strings.Join(candidates, ", "))
}

// findSkillMarkdownPath searches for SKILL.md (case-insensitive) in the given directory.
// Returns the full path if found, empty string otherwise.
func findSkillMarkdownPath(dir string) string {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return ""
	}

	// Try exact case first
	skillPath := filepath.Join(dir, "SKILL.md")
	if stat, err := os.Stat(skillPath); err == nil && !stat.IsDir() {
		return skillPath
	}

	// Case-insensitive fallback: read directory entries
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.EqualFold(entry.Name(), "SKILL.md") {
			return filepath.Join(dir, entry.Name())
		}
	}

	return ""
}

// hasSkillMarkdown checks if the directory contains a SKILL.md file.
func hasSkillMarkdown(dir string) bool {
	skillPath := findSkillMarkdownPath(dir)
	return skillPath != ""
}

// extractSkillNameFromMarkdown reads SKILL.md and extracts the name field.
// Supports both YAML frontmatter (--- delimited) and plain "name:" format.
func extractSkillNameFromMarkdown(dir string) (string, error) {
	skillPath := findSkillMarkdownPath(dir)
	if skillPath == "" {
		return "", fmt.Errorf("SKILL.md not found in %s", dir)
	}
	content, err := os.ReadFile(skillPath)
	if err != nil {
		return "", err
	}

	// Try YAML frontmatter format first
	lines := strings.Split(string(content), "\n")
	inFrontmatter := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" {
			inFrontmatter = !inFrontmatter
			continue
		}
		if inFrontmatter && strings.HasPrefix(trimmed, "name:") {
			// Extract name value, handle quotes and trim spaces
			nameValue := strings.TrimPrefix(trimmed, "name:")
			nameValue = strings.TrimSpace(nameValue)
			// Remove quotes if present
			if len(nameValue) >= 2 {
				first, last := nameValue[0], nameValue[len(nameValue)-1]
				if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
					nameValue = nameValue[1 : len(nameValue)-1]
				}
			}
			return nameValue, nil
		}
	}

	// Fallback: look for "name:" anywhere in the file
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "name:") {
			nameValue := strings.TrimPrefix(trimmed, "name:")
			nameValue = strings.TrimSpace(nameValue)
			if len(nameValue) >= 2 {
				first, last := nameValue[0], nameValue[len(nameValue)-1]
				if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
					nameValue = nameValue[1 : len(nameValue)-1]
				}
			}
			return nameValue, nil
		}
	}

	return "", fmt.Errorf("no name field found in SKILL.md")
}
