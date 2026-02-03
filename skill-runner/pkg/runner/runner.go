package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tensorchord/watchu/gateway/pkg/llmclient"
	"github.com/tensorchord/watchu/skill-runner/pkg/s3"
)

type Config struct {
	Addr             string
	LocalCommand     string
	DockerImage      string
	DockerCommand    string
	K8sNamespace     string
	K8sImage         string
	K8sTTLSeconds    int
	ExecTimeout      time.Duration
	LLMBaseURL       string
	LLMAPIKey        string
	LLMModel         string
	LLMTimeout       time.Duration
	PassEnvVars      map[string]string // Direct environment variables to pass through (key=value pairs)
	WorkspaceBaseDir string           // Base directory for workspaces (must be accessible to host docker daemon)
	// S3 configuration for downloading artifacts
	S3Region     string // S3 region
	S3AccessKey  string // S3 access key (AWS_ACCESS_KEY_ID)
	S3SecretKey  string // S3 secret key (AWS_SECRET_ACCESS_KEY)
}

type RunRequest struct {
	SourceType     string `json:"source_type"`
	SourceRef      string `json:"source_ref"`
	SkillName      string `json:"skill_name,omitempty"`
	ResolvedRef    string `json:"resolved_ref,omitempty"`
	ArtifactPath   string `json:"artifact_path,omitempty"`
	AgentType      string `json:"agent_type"`
	RunnerMode     string `json:"runner_mode"`
	PromptStrategy string `json:"prompt_strategy"`
	PromptInput    string `json:"prompt_input,omitempty"`
	AnalysisID     string `json:"analysis_id,omitempty"`
}

type RunResponse struct {
	RunID       string `json:"run_id"`
	Status      string `json:"status"`
	RootExecID  string `json:"root_exec_id,omitempty"`
	Error       string `json:"error,omitempty"`
	PromptInput string `json:"prompt_input,omitempty"`
}

type RunRecord struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	RootExecID  string    `json:"root_exec_id,omitempty"`
	Error       string    `json:"error,omitempty"`
	Mode        string    `json:"runner_mode"`
	Output      string    `json:"output,omitempty"`
	ExitCode    int       `json:"exit_code,omitempty"`
	Pid         int       `json:"pid,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at,omitempty"`
	PromptInput string    `json:"prompt_input,omitempty"`
}

// S3Client is an interface for S3 operations (for downloading artifacts)
type S3Client interface {
	DownloadToTemp(ctx context.Context, bucket, key string) (string, func(), error)
}

type Runner struct {
	cfg       Config
	log       *slog.Logger
	mu        sync.RWMutex
	runs      map[string]*RunRecord
	re        *regexp.Regexp
	llmClient *llmclient.Client
	llmModel  string
	s3        S3Client // S3 client interface for downloading artifacts
	stopCleanup chan struct{}
	// Runtimes (lazy initialized)
	localRuntime  Runtime
	dockerRuntime Runtime
	k8sRuntime    Runtime
	muRuntime     sync.Mutex
}

func New(cfg Config, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	var llmClient *llmclient.Client
	if cfg.LLMBaseURL != "" {
		timeout := cfg.LLMTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		llmClient = llmclient.NewClient(cfg.LLMBaseURL, cfg.LLMAPIKey, timeout)
	}
	model := cfg.LLMModel
	if model == "" {
		model = "gpt-4o"
	}

	// Initialize S3 client if credentials are provided
	var s3Client S3Client
	if cfg.S3Region != "" && cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
		s3Client = newS3ClientImpl(cfg.S3Region, cfg.S3AccessKey, cfg.S3SecretKey)
		logger.Info("S3 client initialized", slog.String("region", cfg.S3Region))
	}

	return &Runner{
		cfg:         cfg,
		log:         logger,
		runs:        make(map[string]*RunRecord),
		re:          regexp.MustCompile(`(?i)root[_-]?exec[_-]?id["'\s:=]+([a-f0-9-]{16,})`),
		llmClient:   llmClient,
		llmModel:    model,
		s3:          s3Client,
		stopCleanup: make(chan struct{}),
	}
}

// StartCleanup starts a background goroutine that periodically cleans up old run records
func (r *Runner) StartCleanup(maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCleanup:
				return
			case <-ticker.C:
				r.cleanupOldRuns(maxAge)
			}
		}
	}()
}

// StopCleanup stops the cleanup goroutine
func (r *Runner) StopCleanup() {
	close(r.stopCleanup)
}

// getRuntime returns the appropriate runtime for the given mode (lazy initialization).
func (r *Runner) getRuntime(mode string) (Runtime, error) {
	r.muRuntime.Lock()
	defer r.muRuntime.Unlock()

	mode = strings.ToLower(strings.TrimSpace(mode))

	switch mode {
	case "local":
		if r.localRuntime == nil {
			r.localRuntime = NewLocalRuntime(r.cfg.LocalCommand, RuntimeConfig{
				Logger:      r.log,
				ExecTimeout: int(r.cfg.ExecTimeout),
				PassEnvVars: r.cfg.PassEnvVars,
				LLMClient:   r.llmClient,
				LLMModel:    r.llmModel,
			})
		}
		return r.localRuntime, nil
	case "docker":
		if r.dockerRuntime == nil {
			r.dockerRuntime = NewDockerRuntime(r.cfg.DockerImage, r.cfg.DockerCommand, RuntimeConfig{
				Logger:      r.log,
				ExecTimeout: int(r.cfg.ExecTimeout),
				PassEnvVars: r.cfg.PassEnvVars,
				LLMClient:   r.llmClient,
				LLMModel:    r.llmModel,
			})
		}
		return r.dockerRuntime, nil
	case "k8s":
		if r.k8sRuntime == nil {
			r.k8sRuntime = NewK8sRuntime(r.cfg.K8sImage, r.cfg.K8sNamespace, r.cfg.K8sTTLSeconds, RuntimeConfig{
				Logger:      r.log,
				ExecTimeout: int(r.cfg.ExecTimeout),
				PassEnvVars: r.cfg.PassEnvVars,
				LLMClient:   r.llmClient,
				LLMModel:    r.llmModel,
			})
		}
		return r.k8sRuntime, nil
	default:
		return nil, fmt.Errorf("unknown runner_mode: %s", mode)
	}
}

// cleanupOldRuns removes completed run records older than maxAge
func (r *Runner) cleanupOldRuns(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var removed int
	for id, record := range r.runs {
		// Only clean up completed runs (not running)
		if record.Status != "running" {
			if !record.EndedAt.IsZero() && now.Sub(record.EndedAt) > maxAge {
				delete(r.runs, id)
				removed++
			} else if record.EndedAt.IsZero() && now.Sub(record.StartedAt) > maxAge {
				// Fallback: clean up old records without EndedAt set
				delete(r.runs, id)
				removed++
			}
		}
	}
	if removed > 0 {
		r.log.Info("cleaned up old run records", slog.Int("removed", removed), slog.Int("remaining", len(r.runs)))
	}
}

// s3ClientImpl wraps the s3.Client to implement the S3Client interface
type s3ClientImpl struct {
	client *s3.Client
}

func newS3ClientImpl(region, accessKey, secretKey string) S3Client {
	client, err := s3.NewClient(region, accessKey, secretKey)
	if err != nil {
		// Return nil client will be handled by checking if s3 != nil
		return nil
	}
	return &s3ClientImpl{client: client}
}

func (s *s3ClientImpl) DownloadToTemp(ctx context.Context, bucket, key string) (string, func(), error) {
	return s.client.DownloadToTemp(ctx, bucket, key)
}

func (r *Runner) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", r.handleHealth)
	mux.HandleFunc("/run", r.handleRun)
	mux.HandleFunc("/runs/", r.handleRunDetail)
	return mux
}

func (r *Runner) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (r *Runner) handleRun(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var payload RunRequest
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		respondJSON(w, http.StatusBadRequest, RunResponse{Error: err.Error()})
		return
	}
	if strings.TrimSpace(payload.SourceType) == "" || strings.TrimSpace(payload.SourceRef) == "" {
		respondJSON(w, http.StatusBadRequest, RunResponse{Error: "source_type and source_ref are required"})
		return
	}
	if strings.TrimSpace(payload.RunnerMode) == "" {
		respondJSON(w, http.StatusBadRequest, RunResponse{Error: "runner_mode is required"})
		return
	}

	id := uuid.NewString()
	record := &RunRecord{
		ID:        id,
		Status:    "running",
		Mode:      strings.TrimSpace(payload.RunnerMode),
		StartedAt: time.Now().UTC(),
		ExitCode:  -1,
	}

	r.mu.Lock()
	r.runs[id] = record
	r.mu.Unlock()

	go r.execute(id, payload)

	respondJSON(w, http.StatusOK, RunResponse{
		RunID:  id,
		Status: record.Status,
	})
}

func (r *Runner) handleRunDetail(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(req.URL.Path, "/runs/")
	id = strings.TrimSpace(id)
	if id == "" {
		respondJSON(w, http.StatusBadRequest, RunResponse{Error: "run_id is required"})
		return
	}
	r.mu.RLock()
	record, ok := r.runs[id]
	r.mu.RUnlock()
	if !ok {
		respondJSON(w, http.StatusNotFound, RunResponse{Error: "run not found"})
		return
	}
	respondJSON(w, http.StatusOK, record)
}

func (r *Runner) execute(runID string, payload RunRequest) {
	mode := strings.ToLower(strings.TrimSpace(payload.RunnerMode))
	ctx := context.Background()
	if r.cfg.ExecTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.cfg.ExecTimeout)
		defer cancel()
	}

	var output string
	var exitCode int
	var pid int
	var execErr error

	cleanup, prepErr := r.prepareSkill(ctx, &payload)
	if cleanup != nil {
		defer cleanup()
	}
	if prepErr != nil {
		execErr = prepErr
		output = prepErr.Error()
		exitCode = -1
	} else {
		r.logRunContext(runID, payload)
	}

	// Get the appropriate runtime
	runtime, runtimeErr := r.getRuntime(mode)
	if runtimeErr != nil {
		execErr = runtimeErr
		output = runtimeErr.Error()
		exitCode = -1
	} else if execErr == nil {
		// Validate the runtime configuration
		if validateErr := runtime.Validate(); validateErr != nil {
			execErr = validateErr
			output = validateErr.Error()
			exitCode = -1
		} else {
			// Execute the run
			output, exitCode, pid, execErr = runtime.Execute(ctx, payload)
		}
	}

	status := "completed"
	if execErr != nil {
		status = "failed"
	}
	rootExecID := r.extractRootExecID(output)
	if mode == "k8s" && execErr == nil {
		status = "running"
	}

	r.mu.Lock()
	record := r.runs[runID]
	if record != nil {
		record.Status = status
		record.Output = output
		record.ExitCode = exitCode
		record.Pid = pid
		record.RootExecID = rootExecID
		record.EndedAt = time.Now().UTC()
		record.PromptInput = payload.PromptInput
		if execErr != nil {
			record.Error = execErr.Error()
		}
	}
	r.mu.Unlock()

	if execErr != nil {
		r.log.Error("run failed",
			slog.String("run_id", runID),
			slog.String("error", execErr.Error()),
			slog.Int("exit_code", exitCode),
			slog.String("output", truncateOutput(output, 4096)),
		)
	} else {
		r.log.Info("run completed",
			slog.String("run_id", runID),
			slog.Int("exit_code", exitCode),
			slog.String("output", truncateOutput(output, 1024)),
		)
	}
}

// shellQuote is a utility function for quoting shell arguments.
// It is kept here for backward compatibility but is also used by local.go
func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func (r *Runner) prepareSkill(ctx context.Context, payload *RunRequest) (func(), error) {
	var cleanup func()
	sourceType := strings.ToLower(strings.TrimSpace(payload.SourceType))
	artifactPath := strings.TrimSpace(payload.ArtifactPath)

	if artifactPath == "" {
		switch sourceType {
		case "local":
			artifactPath = strings.TrimSpace(payload.SourceRef)
		case "github":
			if strings.TrimSpace(payload.SourceRef) != "" {
				dir, err := os.MkdirTemp("", "skill-runner-git-")
				if err != nil {
					return nil, err
				}
				cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", payload.SourceRef, dir)
				out, err := cmd.CombinedOutput()
				if err != nil {
					_ = os.RemoveAll(dir)
					return nil, fmt.Errorf("git clone failed: %w: %s", err, strings.TrimSpace(string(out)))
				}
				cleanup = func() { _ = os.RemoveAll(dir) }
				artifactPath = dir
			}
		}
	}

	// Handle S3 paths (s3://bucket/key)
	if s3.IsS3Path(artifactPath) {
		bucket, key, err := s3.ParseS3Path(artifactPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse S3 path %s: %w", artifactPath, err)
		}
		if r.s3 == nil {
			return nil, fmt.Errorf("S3 path provided but S3 client not configured (missing S3 credentials)")
		}
		localPath, s3Cleanup, err := r.s3.DownloadToTemp(ctx, bucket, key)
		if err != nil {
			return nil, fmt.Errorf("failed to download from S3 %s: %w", artifactPath, err)
		}
		r.log.Info("downloaded artifact from S3",
			slog.String("s3_path", artifactPath),
			slog.String("local_path", localPath))
		artifactPath = localPath
		if s3Cleanup != nil {
			prev := cleanup
			cleanup = func() {
				s3Cleanup()
				if prev != nil {
					prev()
				}
			}
		}
	}

	if artifactPath != "" {
		resolved, extraCleanup, err := resolveArtifactPath(artifactPath)
		if err != nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, err
		}
		if extraCleanup != nil {
			prev := cleanup
			cleanup = func() {
				extraCleanup()
				if prev != nil {
					prev()
				}
			}
		}
		payload.ArtifactPath = resolved
	}

	// Locate skill directory (works for both named and unnamed skills)
	// When SkillName is empty, locateSkillDir will auto-select the first skill found
	if payload.ArtifactPath != "" {
		skillDir, err := locateSkillDir(payload.ArtifactPath, payload.SkillName)
		if err != nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, err
		}
		payload.ArtifactPath = skillDir
	}

	// Save original skill path for prompt generation
	originalSkillPath := payload.ArtifactPath

	// For claude-code, set up .claude/skills/ structure
	if strings.EqualFold(strings.TrimSpace(payload.AgentType), "claude-code") && payload.ArtifactPath != "" {
		setupDir, err := r.setupClaudeCodeSkillStructure(payload.ArtifactPath)
		if err != nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, fmt.Errorf("failed to setup claude-code skill structure: %w", err)
		}
		if setupDir != "" {
			// Update artifact path to the parent directory containing .claude/skills/
			payload.ArtifactPath = setupDir
			// Add cleanup for the setup directory
			prev := cleanup
			cleanup = func() {
				_ = os.RemoveAll(setupDir)
				if prev != nil {
					prev()
				}
			}
		}
	}

	if strings.EqualFold(strings.TrimSpace(payload.PromptStrategy), "from-skill") && strings.TrimSpace(payload.PromptInput) == "" {
		// Use original skill path for prompt generation
		skillPathForPrompt := originalSkillPath
		if strings.EqualFold(strings.TrimSpace(payload.AgentType), "claude-code") {
			// For claude-code, the skill was copied to .claude/skills/{name}
			// We can still use the original path since it has SKILL.md
			skillPathForPrompt = originalSkillPath
		}
		if skillPathForPrompt != "" {
			prompt, err := r.generatePromptFromSkill(ctx, skillPathForPrompt)
			if err != nil {
				if cleanup != nil {
					cleanup()
				}
				return nil, fmt.Errorf("failed to generate prompt from skill: %w", err)
			}
			if prompt == "" {
				if cleanup != nil {
					cleanup()
				}
				return nil, fmt.Errorf("skill generated empty prompt from %s", skillPathForPrompt)
			}
			payload.PromptInput = prompt
		}
	}

	return cleanup, nil
}

func (r *Runner) setupClaudeCodeSkillStructure(skillPath string) (string, error) {
	// Use configured workspace base directory (shared volume) or fallback to system temp
	baseDir := r.cfg.WorkspaceBaseDir
	if baseDir == "" {
		// Fallback to system temp directory for backward compatibility
		baseDir = os.TempDir()
	} else {
		// Ensure base directory exists
		if err := os.MkdirAll(baseDir, 0o755); err != nil {
			return "", fmt.Errorf("failed to create workspace base directory: %w", err)
		}
	}

	// Create a temporary directory for the claude-code workspace
	tmpDir, err := os.MkdirTemp(baseDir, "claude-code-workspace-")
	if err != nil {
		return "", err
	}

	// Change ownership to uid=100 (claude user in agent container)
	// This is required because agent containers run as uid=100 to satisfy
	// Claude Code CLI's security restriction on --dangerously-skip-permissions
	if err := os.Chown(tmpDir, 100, 101); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to chown workspace directory: %w", err)
	}

	// Get the skill folder name
	skillName := filepath.Base(skillPath)

	// Create .claude/skills/ directory structure
	claudeSkillsDir := filepath.Join(tmpDir, ".claude", "skills")
	if err := os.MkdirAll(claudeSkillsDir, 0o755); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", err
	}

	// Copy skill folder to .claude/skills/
	claudeTargetPath := filepath.Join(claudeSkillsDir, skillName)

	if err := copyDir(skillPath, claudeTargetPath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to copy skill directory to .claude/skills: %w", err)
	}

	// Ensure all files in workspace are owned by uid=100
	if err := chownR(tmpDir, 100, 101); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to chown workspace files: %w", err)
	}

	r.log.Info("setup claude-code skill structure",
		slog.String("original", skillPath),
		slog.String("workspace", tmpDir),
		slog.String("claude_skill_path", claudeTargetPath),
	)

	return tmpDir, nil
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, 0o644)
}

func chownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(name, uid, gid)
	})
}

func (r *Runner) generatePromptFromSkill(ctx context.Context, dir string) (string, error) {
	path := filepath.Join(dir, "SKILL.md")
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read SKILL.md: %w", err)
	}
	const maxSize = 12000
	if len(content) > maxSize {
		content = content[:maxSize]
	}
	skillContent := strings.TrimSpace(string(content))
	if skillContent == "" {
		return "", fmt.Errorf("SKILL.md is empty")
	}

	// Extract skill name from SKILL.md (first heading or filename)
	skillName := extractSkillName(skillContent, dir)

	if r.llmClient == nil {
		r.log.Warn("LLM client not configured, using fallback prompt")
		return fmt.Sprintf("Use the %s skill:\n\n%s\n\nRun a minimal safe example.", skillName, skillContent), nil
	}

	systemPrompt := `You are an AI assistant that helps test Claude Code skills. Your task is to:
1. Analyze the provided SKILL.md file to understand what the skill does
2. Generate a concise, practical user request that would effectively trigger and demonstrate this skill
3. CRITICAL: The request MUST explicitly mention the skill name (e.g., "Use the XXX skill to...", "Using the XXX skill...", "Apply the XXX skill to...")
4. Keep it brief (1-2 sentences) and actionable
5. Do NOT include explanations or meta-commentary - only output the user request itself

Respond with ONLY the user request text, nothing else.`

	userPrompt := fmt.Sprintf("Here is the SKILL.md content:\n\n%s\n\n\nThe skill name is: %s\n\nGenerate a brief user request that would trigger this skill. IMPORTANT: Always include the skill name \"%s\" in your request. Output ONLY the request text, no explanation.", skillContent, skillName, skillName)

	prompt, err := r.llmClient.Complete(ctx, r.llmModel, systemPrompt+"\n\n"+userPrompt, 0.7, 500)
	if err != nil {
		r.log.Warn("LLM prompt generation failed, using fallback", slog.String("error", err.Error()))
		return fmt.Sprintf("Use the %s skill:\n\n%s\n\nRun a minimal safe example.", skillName, skillContent), nil
	}

	generatedPrompt := strings.TrimSpace(prompt)
	if generatedPrompt == "" {
		return fmt.Sprintf("Use the %s skill:\n\n%s\n\nRun a minimal safe example.", skillName, skillContent), nil
	}

	r.log.Info("generated prompt from SKILL.md using LLM",
		slog.String("skill_name", skillName),
		slog.Int("skill_md_len", len(skillContent)),
		slog.Int("generated_prompt_len", len(generatedPrompt)),
	)

	return generatedPrompt, nil
}

func extractSkillName(content, dir string) string {
	// Try to extract name from SKILL.md first
	if dir != "" {
		if name, err := extractSkillNameFromMarkdown(dir); err == nil && name != "" {
			return name
		}
		// Fallback to directory name
		return filepath.Base(dir)
	}
	return "skill"
}

func (r *Runner) extractRootExecID(output string) string {
	if output == "" {
		return ""
	}
	match := r.re.FindStringSubmatch(output)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func (r *Runner) logRunContext(runID string, payload RunRequest) {
	prompt := strings.TrimSpace(payload.PromptInput)
	summary := r.describeSkillTree(payload.ArtifactPath)
	cwdListing := r.listDirEntries(payload.ArtifactPath, 80)
	mode := strings.ToLower(strings.TrimSpace(payload.RunnerMode))
	r.log.Info("run context",
		slog.String("run_id", runID),
		slog.String("source_type", strings.TrimSpace(payload.SourceType)),
		slog.String("source_ref", strings.TrimSpace(payload.SourceRef)),
		slog.String("artifact_path", strings.TrimSpace(payload.ArtifactPath)),
		slog.String("prompt_strategy", strings.TrimSpace(payload.PromptStrategy)),
		slog.Int("prompt_len", len(prompt)),
		slog.String("prompt_preview", truncateOutput(prompt, 400)),
		slog.String("skill_tree", summary),
		slog.String("cwd", strings.TrimSpace(payload.ArtifactPath)),
		slog.String("cwd_entries", cwdListing),
		slog.String("runner_mode", mode),
		slog.String("local_cmd", r.cfg.LocalCommand),
		slog.String("docker_image", r.cfg.DockerImage),
		slog.String("docker_command", r.cfg.DockerCommand),
		slog.String("k8s_image", r.cfg.K8sImage),
	)
}

func (r *Runner) describeSkillTree(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return ""
	}

	const (
		maxDepth   = 3
		maxEntries = 200
	)
	var (
		builder strings.Builder
		count   int
	)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		depth := strings.Count(rel, string(os.PathSeparator))
		if d.IsDir() && depth >= maxDepth {
			return fs.SkipDir
		}
		if depth > maxDepth {
			return nil
		}
		count++
		if count > maxEntries {
			return fs.SkipDir
		}
		kind := "file"
		if d.IsDir() {
			kind = "dir"
		}
		builder.WriteString(fmt.Sprintf("%s:%s\n", kind, rel))
		return nil
	})

	result := strings.TrimSpace(builder.String())
	if count > maxEntries {
		return result + "\n...(truncated)"
	}
	return result
}

func (r *Runner) listDirEntries(root string, max int) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	if max <= 0 {
		max = 50
	}
	var builder strings.Builder
	for i, entry := range entries {
		if i >= max {
			builder.WriteString("...(truncated)")
			break
		}
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		builder.WriteString(name)
		if i < len(entries)-1 && i < max-1 {
			builder.WriteString(", ")
		}
	}
	return builder.String()
}
