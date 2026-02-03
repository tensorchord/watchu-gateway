package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewRunner(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "default config",
			cfg: Config{
				Addr:         ":8091",
				LocalCommand: "claude",
			},
			wantErr: false,
		},
		{
			name: "with LLM config",
			cfg: Config{
				Addr:         ":8091",
				LocalCommand: "claude",
				LLMBaseURL:   "http://example.com",
				LLMAPIKey:    "test-key",
				LLMModel:     "gpt-4",
				LLMTimeout:   30,
				ExecTimeout:  600,
			},
			wantErr: false,
		},
		{
			name: "with env vars",
			cfg: Config{
				Addr:         ":8091",
				LocalCommand: "claude",
				PassEnvVars: map[string]string{
					"KEY1": "value1",
					"KEY2": "value2",
				},
			},
			wantErr: false,
		},
		{
			name: "with docker config",
			cfg: Config{
				Addr:          ":8091",
				LocalCommand:  "claude",
				DockerImage:   "ghcr.io/tensorchord/watchu-claude-code-agent:latest",
				DockerCommand: "claude --dangerously-skip-permissions -p",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New(tt.cfg, nil)
			if r == nil {
				t.Fatal("New() returned nil")
			}
		})
	}
}

func TestExtractRootExecID(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		want      string
		wantEmpty bool
	}{
		{
			name:      "empty output",
			output:    "",
			wantEmpty: true,
		},
		{
			name:      "no match",
			output:    "some random text without root exec id",
			wantEmpty: true,
		},
		{
			name:   "match root_exec_id format",
			output: `{"root_exec_id":"aa685b50-d66f-1124-3982-6228-22072032048"}`,
			want:   "aa685b50-d66f-1124-3982-6228-22072032048",
		},
		{
			name:   "match root-exec-id format",
			output: `root-exec-id: aa685b50-d66f-1124-3982-6228-22072032048`,
			want:   "aa685b50-d66f-1124-3982-6228-22072032048",
		},
		{
			name:   "match RootExecId format",
			output: `RootExecId = 'aa685b50-d66f-1124-3982-6228-22072032048'`,
			want:   "aa685b50-d66f-1124-3982-6228-22072032048",
		},
		{
			name:   "long UUID format",
			output: `root_exec_id=aa685b50d66f11243982622822072032048abcd1234`,
			want:   "aa685b50d66f11243982622822072032048abcd1234",
		},
		{
			name:   "realistic output with system message",
			output: `{"type":"system","root_exec_id":"aa685b50-d66f-1124-3982-6228-22072032048","cwd":"/tmp"}`,
			want:   "aa685b50-d66f-1124-3982-6228-22072032048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New(Config{}, nil)
			got := r.extractRootExecID(tt.output)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("extractRootExecID() = %q, want empty", got)
				}
			} else {
				if got != tt.want {
					t.Errorf("extractRootExecID() = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestBuildEnvMap(t *testing.T) {
	tests := []struct {
		name string
		req  RunRequest
		want map[string]string
	}{
		{
			name: "minimal request",
			req: RunRequest{
				SourceType:     "upload",
				SourceRef:      "test-skill",
				AgentType:      "claude-code",
				RunnerMode:     "local",
				PromptStrategy: "from-skill",
			},
			want: map[string]string{
				"SKILL_SOURCE_TYPE":     "upload",
				"SKILL_SOURCE_REF":      "test-skill",
				"SKILL_AGENT_TYPE":      "claude-code",
				"SKILL_RUNNER_MODE":     "local",
				"SKILL_PROMPT_STRATEGY": "from-skill",
				"SHELL":                 "/bin/sh",
			},
		},
		{
			name: "with all fields",
			req: RunRequest{
				SourceType:     "git",
				SourceRef:      "https://github.com/user/repo",
				SkillName:      "example-skill",
				ResolvedRef:    "main",
				ArtifactPath:   "/path/to/skill",
				AgentType:      "claude-code",
				RunnerMode:     "docker",
				PromptStrategy: "custom",
				PromptInput:    "test prompt",
			},
			want: map[string]string{
				"SKILL_SOURCE_TYPE":     "git",
				"SKILL_SOURCE_REF":      "https://github.com/user/repo",
				"SKILL_NAME":            "example-skill",
				"SKILL_RESOLVED_REF":    "main",
				"SKILL_ARTIFACT_PATH":   "/path/to/skill",
				"SKILL_AGENT_TYPE":      "claude-code",
				"SKILL_RUNNER_MODE":     "docker",
				"SKILL_PROMPT_STRATEGY": "custom",
				"SKILL_PROMPT":          "test prompt",
				"SHELL":                 "/bin/sh",
			},
		},
		{
			name: "with empty optional fields",
			req: RunRequest{
				SourceType:     "upload",
				SourceRef:      "test",
				AgentType:      "claude-code",
				RunnerMode:     "local",
				PromptStrategy: "from-skill",
				ResolvedRef:    "",
				PromptInput:    "",
			},
			want: map[string]string{
				"SKILL_SOURCE_TYPE":     "upload",
				"SKILL_SOURCE_REF":      "test",
				"SKILL_AGENT_TYPE":      "claude-code",
				"SKILL_RUNNER_MODE":     "local",
				"SKILL_PROMPT_STRATEGY": "from-skill",
				"SHELL":                 "/bin/sh",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildEnvMap(tt.req)
			if len(got) != len(tt.want) {
				t.Errorf("buildEnvMap() returned %d vars, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("buildEnvMap()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestLocateSkillDir(t *testing.T) {
	baseDir := t.TempDir()

	skillsDir := filepath.Join(baseDir, "skills", "alpha")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillsDir, "SKILL.md"), []byte("# alpha"), 0o644); err != nil {
		t.Fatalf("write SKILL.md failed: %v", err)
	}
	found, err := locateSkillDir(baseDir, "alpha")
	if err != nil {
		t.Fatalf("locateSkillDir failed: %v", err)
	}
	if found != skillsDir {
		t.Fatalf("expected %q, got %q", skillsDir, found)
	}

	baseDir2 := t.TempDir()
	altDir := filepath.Join(baseDir2, "beta")
	if err := os.MkdirAll(altDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(altDir, "SKILL.md"), []byte("# beta"), 0o644); err != nil {
		t.Fatalf("write SKILL.md failed: %v", err)
	}
	found, err = locateSkillDir(baseDir2, "beta")
	if err != nil {
		t.Fatalf("locateSkillDir failed: %v", err)
	}
	if found != altDir {
		t.Fatalf("expected %q, got %q", altDir, found)
	}

	baseDir3 := filepath.Join(t.TempDir(), "gamma")
	if err := os.MkdirAll(baseDir3, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir3, "SKILL.md"), []byte("# gamma"), 0o644); err != nil {
		t.Fatalf("write SKILL.md failed: %v", err)
	}
	found, err = locateSkillDir(baseDir3, "gamma")
	if err != nil {
		t.Fatalf("locateSkillDir failed: %v", err)
	}
	if found != baseDir3 {
		t.Fatalf("expected %q, got %q", baseDir3, found)
	}

	_, err = locateSkillDir(baseDir, "missing")
	if err == nil {
		t.Fatalf("expected error for missing skill")
	}
}

func TestExtractSkillNameFromMarkdown(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		want      string
		wantError bool
	}{
		{
			name: "name field without quotes",
			content: `---
name: vercel-react-best-practices
---
# Skill Content`,
			want:      "vercel-react-best-practices",
			wantError: false,
		},
		{
			name: "name field with single quotes",
			content: `---
name: 'remotion-best-practices'
---
# Skill Content`,
			want:      "remotion-best-practices",
			wantError: false,
		},
		{
			name: "name field with double quotes",
			content: `---
name: "seo-audit"
---
# Skill Content`,
			want:      "seo-audit",
			wantError: false,
		},
		{
			name: "name field with extra spaces",
			content: `---
name:  test-skill
---
# Skill Content`,
			want:      "test-skill",
			wantError: false,
		},
		{
			name: "no name field",
			content: `---
description: A skill
---
# Skill Content`,
			wantError: true,
		},
		{
			name: "name field without yaml frontmatter",
			content: `name: simple-skill
# Skill Content`,
			want:      "simple-skill",
			wantError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			skillPath := filepath.Join(tmpDir, "SKILL.md")
			if err := os.WriteFile(skillPath, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write SKILL.md failed: %v", err)
			}

			got, err := extractSkillNameFromMarkdown(tmpDir)
			if tt.wantError {
				if err == nil {
					t.Errorf("extractSkillNameFromMarkdown() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("extractSkillNameFromMarkdown() failed: %v", err)
				}
				if got != tt.want {
					t.Errorf("extractSkillNameFromMarkdown() = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestLocateSkillDirByNameField(t *testing.T) {
	baseDir := t.TempDir()
	skillsDir := filepath.Join(baseDir, "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	// Create skill directories where directory name != SKILL.md name field
	testCases := []struct {
		dirName     string
		skillName   string
		skillNameInMd string
	}{
		{"react-best-practices", "vercel-react-best-practices", "vercel-react-best-practices"},
		{"remotion-practices", "remotion-best-practices", "remotion-best-practices"},
		{"seo", "seo-audit", "seo-audit"},
	}

	for _, tc := range testCases {
		dirPath := filepath.Join(skillsDir, tc.dirName)
		if err := os.MkdirAll(dirPath, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		content := "---\nname: " + tc.skillNameInMd + "\n---\n# " + tc.skillNameInMd
		if err := os.WriteFile(filepath.Join(dirPath, "SKILL.md"), []byte(content), 0o644); err != nil {
			t.Fatalf("write SKILL.md failed: %v", err)
		}
	}

	// Test lookup by name field (not directory name)
	for _, tc := range testCases {
		t.Run(tc.skillName, func(t *testing.T) {
			found, err := locateSkillDir(baseDir, tc.skillName)
			if err != nil {
				t.Fatalf("locateSkillDir(%q) failed: %v", tc.skillName, err)
			}
			expectedDir := filepath.Join(skillsDir, tc.dirName)
			if found != expectedDir {
				t.Errorf("locateSkillDir(%q) = %q, want %q", tc.skillName, found, expectedDir)
			}
		})
	}

	// Test that directory name still works for backward compatibility
	t.Run("directory name still works", func(t *testing.T) {
		found, err := locateSkillDir(baseDir, "react-best-practices")
		if err != nil {
			t.Fatalf("locateSkillDir by directory name failed: %v", err)
		}
		expectedDir := filepath.Join(skillsDir, "react-best-practices")
		if found != expectedDir {
			t.Errorf("locateSkillDir by directory name = %q, want %q", found, expectedDir)
		}
	})
}

func TestLocateSkillDirAutoSelectFirst(t *testing.T) {
	// Test 1: Single-skill repo (SKILL.md at root) - backward compatible
	t.Run("single skill repo with root SKILL.md", func(t *testing.T) {
		baseDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(baseDir, "SKILL.md"), []byte("# Root Skill"), 0o644); err != nil {
			t.Fatalf("write SKILL.md failed: %v", err)
		}

		found, err := locateSkillDir(baseDir, "")
		if err != nil {
			t.Fatalf("locateSkillDir failed: %v", err)
		}
		if found != baseDir {
			t.Errorf("expected baseDir %q, got %q", baseDir, found)
		}
	})

	// Test 2: Multi-skill repo - auto select first skill
	t.Run("multi-skill repo auto selects first", func(t *testing.T) {
		baseDir := t.TempDir()
		skillsDir := filepath.Join(baseDir, "skills")
		if err := os.MkdirAll(skillsDir, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}

		// Create multiple skills
		skill1 := filepath.Join(skillsDir, "first-skill")
		skill2 := filepath.Join(skillsDir, "second-skill")
		if err := os.MkdirAll(skill1, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		if err := os.MkdirAll(skill2, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skill1, "SKILL.md"), []byte("name: first"), 0o644); err != nil {
			t.Fatalf("write SKILL.md failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skill2, "SKILL.md"), []byte("name: second"), 0o644); err != nil {
			t.Fatalf("write SKILL.md failed: %v", err)
		}

		// Auto-select first skill when skillName is empty
		found, err := locateSkillDir(baseDir, "")
		if err != nil {
			t.Fatalf("locateSkillDir failed: %v", err)
		}
		// First skill found (os.ReadDir ordering)
		if found != skill1 && found != skill2 {
			t.Errorf("expected one of %q or %q, got %q", skill1, skill2, found)
		}
	})

	// Test 3: Repo with no skill - should return error
	t.Run("repo with no skill returns error", func(t *testing.T) {
		baseDir := t.TempDir()
		// Only README.md, no SKILL.md
		if err := os.WriteFile(filepath.Join(baseDir, "README.md"), []byte("# Readme"), 0o644); err != nil {
			t.Fatalf("write README.md failed: %v", err)
		}

		_, err := locateSkillDir(baseDir, "")
		if err == nil {
			t.Fatal("expected error for repo with no skill, got nil")
		}
	})

	// Test 4: Empty skills/ directory
	t.Run("empty skills directory returns error", func(t *testing.T) {
		baseDir := t.TempDir()
		skillsDir := filepath.Join(baseDir, "skills")
		if err := os.MkdirAll(skillsDir, 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}

		_, err := locateSkillDir(baseDir, "")
		if err == nil {
			t.Fatal("expected error for empty skills directory, got nil")
		}
	})
}

func TestBuildEnv(t *testing.T) {
	tests := []struct {
		name      string
		req       RunRequest
		minLength int
	}{
		{
			name: "minimal request",
			req: RunRequest{
				SourceType:     "upload",
				SourceRef:      "test-skill",
				AgentType:      "claude-code",
				RunnerMode:     "local",
				PromptStrategy: "from-skill",
			},
			minLength: 5,
		},
		{
			name: "with all fields",
			req: RunRequest{
				SourceType:     "git",
				SourceRef:      "https://github.com/user/repo",
				ResolvedRef:    "main",
				ArtifactPath:   "/path/to/skill",
				AgentType:      "claude-code",
				RunnerMode:     "docker",
				PromptStrategy: "custom",
				PromptInput:    "test prompt",
			},
			minLength: 8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildEnv(tt.req)
			if len(got) < tt.minLength {
				t.Errorf("buildEnv() returned %d vars, want at least %d", len(got), tt.minLength)
			}
			// Check format: each should be KEY=VALUE
			for _, env := range got {
				if !strings.Contains(env, "=") {
					t.Errorf("buildEnv() returned invalid env var: %q", env)
				}
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{
		Addr:         ":8091",
		LocalCommand: "claude",
	}

	if cfg.LLMTimeout == 0 {
		cfg.LLMTimeout = 30 * time.Second
	}
	if cfg.ExecTimeout == 0 {
		cfg.ExecTimeout = 30 * time.Minute
	}
	if cfg.K8sTTLSeconds == 0 {
		cfg.K8sTTLSeconds = 600
	}

	if cfg.LLMTimeout != 30*time.Second {
		t.Errorf("Default LLMTimeout = %v, want %v", cfg.LLMTimeout, 30*time.Second)
	}
	if cfg.ExecTimeout != 30*time.Minute {
		t.Errorf("Default ExecTimeout = %v, want %v", cfg.ExecTimeout, 30*time.Minute)
	}
	if cfg.K8sTTLSeconds != 600 {
		t.Errorf("Default K8sTTLSeconds = %d, want %d", cfg.K8sTTLSeconds, 600)
	}
}
