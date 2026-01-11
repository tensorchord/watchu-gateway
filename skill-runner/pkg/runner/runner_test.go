package runner

import (
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
			},
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
			want: map[string]string{
				"SKILL_SOURCE_TYPE":     "git",
				"SKILL_SOURCE_REF":      "https://github.com/user/repo",
				"SKILL_RESOLVED_REF":    "main",
				"SKILL_ARTIFACT_PATH":   "/path/to/skill",
				"SKILL_AGENT_TYPE":      "claude-code",
				"SKILL_RUNNER_MODE":     "docker",
				"SKILL_PROMPT_STRATEGY": "custom",
				"SKILL_PROMPT":          "test prompt",
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

