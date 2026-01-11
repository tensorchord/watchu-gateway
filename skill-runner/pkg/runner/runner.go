package runner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tensorchord/watchu/gateway/pkg/llmclient"
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
}

type RunRequest struct {
	SourceType     string `json:"source_type"`
	SourceRef      string `json:"source_ref"`
	ResolvedRef    string `json:"resolved_ref,omitempty"`
	ArtifactPath   string `json:"artifact_path,omitempty"`
	AgentType      string `json:"agent_type"`
	RunnerMode     string `json:"runner_mode"`
	PromptStrategy string `json:"prompt_strategy"`
	PromptInput    string `json:"prompt_input,omitempty"`
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

type Runner struct {
	cfg       Config
	log       *slog.Logger
	mu        sync.RWMutex
	runs      map[string]*RunRecord
	re        *regexp.Regexp
	llmClient *llmclient.Client
	llmModel  string
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
	return &Runner{
		cfg:       cfg,
		log:       logger,
		runs:      make(map[string]*RunRecord),
		re:        regexp.MustCompile(`(?i)root[_-]?exec[_-]?id["'\s:=]+([a-f0-9-]{16,})`),
		llmClient: llmClient,
		llmModel:  model,
	}
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

	switch mode {
	case "local":
		if execErr == nil {
			output, exitCode, pid, execErr = r.runLocal(ctx, payload)
		}
	case "docker":
		if execErr == nil {
			output, exitCode, pid, execErr = r.runDocker(ctx, payload)
		}
	case "k8s":
		if execErr == nil {
			output, exitCode, pid, execErr = r.runK8s(ctx, payload)
		}
	default:
		execErr = fmt.Errorf("unknown runner_mode: %s", mode)
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

func (r *Runner) runLocal(ctx context.Context, payload RunRequest) (string, int, int, error) {
	if r.cfg.LocalCommand == "" {
		return "", -1, 0, errors.New("local command not configured")
	}
	return r.runLocalDetached(ctx, payload)
}

func (r *Runner) runLocalDetached(ctx context.Context, payload RunRequest) (string, int, int, error) {
	cmd, args, err := splitCommand(r.cfg.LocalCommand)
	if err != nil {
		return "", -1, 0, err
	}
	workdir := strings.TrimSpace(payload.ArtifactPath)
	if workdir == "" {
		if cwd, err := os.Getwd(); err == nil {
			workdir = cwd
		}
	}

	tmpDir, err := os.MkdirTemp("", "skill-runner-local-")
	if err != nil {
		return "", -1, 0, err
	}
	outputPath := filepath.Join(tmpDir, "output.log")
	exitPath := filepath.Join(tmpDir, "exit.code")
	promptPath := filepath.Join(tmpDir, "prompt.txt")
	pidPath := filepath.Join(tmpDir, "pid")
	scriptPath := filepath.Join(tmpDir, "run.sh")

	if payload.PromptInput != "" {
		if err := os.WriteFile(promptPath, []byte(payload.PromptInput), 0o600); err != nil {
			return "", -1, 0, err
		}
	}

	script := r.buildDetachedScript(workdir, cmd, args, promptPath, outputPath, exitPath, pidPath)
	r.log.Info("generated run script",
		slog.String("script", script),
	)
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return "", -1, 0, err
	}

	launch := exec.Command("sh", "-c", fmt.Sprintf("setsid %s >/dev/null 2>&1 & echo $!", shellQuote(scriptPath)))
	launch.Env = append(os.Environ(), buildEnv(payload)...)
	launchOut, err := launch.Output()
	if err != nil {
		return "", -1, 0, err
	}
	launchPID := strings.TrimSpace(string(launchOut))
	pid := 0
	if launchPID != "" {
		if parsed, err := strconv.Atoi(launchPID); err == nil {
			pid = parsed
		}
	}

	r.log.Info("local run detached",
		slog.String("output_path", outputPath),
		slog.String("exit_path", exitPath),
		slog.Int("pid", pid),
	)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", -1, pid, ctx.Err()
		case <-ticker.C:
			if _, err := os.Stat(exitPath); err == nil {
				exitCode, readErr := readExitCode(exitPath)
				if readErr != nil {
					return "", -1, pid, readErr
				}
				output, _ := os.ReadFile(outputPath)
				if parsed, err := readExitCode(pidPath); err == nil {
					pid = parsed
				}
				return strings.TrimSpace(string(output)), exitCode, pid, nil
			}
		}
	}
}

func (r *Runner) buildDetachedScript(workdir, cmd string, args []string, promptPath, outputPath, exitPath, pidPath string) string {
	var builder strings.Builder
	builder.WriteString("#!/bin/sh\n")
	builder.WriteString("cd ")
	builder.WriteString(shellQuote(workdir))
	builder.WriteString(" || exit 1\n")
	builder.WriteString("if [ -f ")
	builder.WriteString(shellQuote(promptPath))
	builder.WriteString(" ]; then\n")
	builder.WriteString("  ")
	builder.WriteString(shellQuote(cmd))
	for _, arg := range args {
		builder.WriteString(" ")
		builder.WriteString(shellQuote(arg))
	}
	builder.WriteString(" < ")
	builder.WriteString(shellQuote(promptPath))
	builder.WriteString(" > ")
	builder.WriteString(shellQuote(outputPath))
	builder.WriteString(" 2>&1 &\n")
	builder.WriteString("  child=$!\n")
	builder.WriteString("else\n")
	builder.WriteString("  ")
	builder.WriteString(shellQuote(cmd))
	for _, arg := range args {
		builder.WriteString(" ")
		builder.WriteString(shellQuote(arg))
	}
	builder.WriteString(" > ")
	builder.WriteString(shellQuote(outputPath))
	builder.WriteString(" 2>&1 &\n")
	builder.WriteString("  child=$!\n")
	builder.WriteString("fi\n")
	builder.WriteString("echo $child > ")
	builder.WriteString(shellQuote(pidPath))
	builder.WriteString("\n")
	builder.WriteString("wait $child\n")
	builder.WriteString("rc=$?\n")
	builder.WriteString("echo $rc > ")
	builder.WriteString(shellQuote(exitPath))
	builder.WriteString("\n")
	return builder.String()
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func splitCommand(command string) (string, []string, error) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "", nil, errors.New("local command not configured")
	}
	return fields[0], fields[1:], nil
}

func readExitCode(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return -1, err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return -1, errors.New("exit code missing")
	}
	code, err := strconv.Atoi(value)
	if err != nil {
		return -1, err
	}
	return code, nil
}

func (r *Runner) runDocker(ctx context.Context, payload RunRequest) (string, int, int, error) {
	if r.cfg.DockerImage == "" {
		return "", -1, 0, errors.New("docker image not configured")
	}

	args := []string{"run", "--rm"}

	// Run as current user to avoid permission issues with mounted volumes
	if os.Getuid() != 0 {
		args = append(args, fmt.Sprintf("--user=%d:%d", os.Getuid(), os.Getgid()))
	}

	// Check if we need stdin (for prompt input)
	prompt := strings.TrimSpace(payload.PromptInput)
	needsStdin := prompt != "" && strings.Contains(r.cfg.DockerCommand, "-p")

	// Add -i flag if stdin is needed
	if needsStdin {
		args = append(args, "-i")
	}

	if payload.ArtifactPath != "" {
		hostPath := payload.ArtifactPath
		// Mount the workspace to /home/claude so Claude Code can find .claude/skills/
		// This is important because Claude Code looks for skills in $HOME/.claude/skills/
		containerPath := "/home/claude"
		// Use rw mount to allow Claude to write config files like .claude.json
		args = append(args, "-v", fmt.Sprintf("%s:%s", hostPath, containerPath))
		args = append(args, "-w", containerPath)
		// artifact_path remains the same for tracking purposes
	}

	// Add skill metadata environment variables
	for _, env := range buildEnv(payload) {
		args = append(args, "-e", env)
	}

	// Pass through direct environment variables from config
	for key, value := range r.cfg.PassEnvVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	args = append(args, r.cfg.DockerImage)
	if strings.TrimSpace(r.cfg.DockerCommand) != "" {
		args = append(args, strings.Fields(r.cfg.DockerCommand)...)
	}

	r.log.Info("docker command built",
		slog.Int("env_direct_count", len(r.cfg.PassEnvVars)))

	cmd := exec.CommandContext(ctx, "docker", args...)

	// Set stdin if prompt is available
	if needsStdin {
		cmd.Stdin = strings.NewReader(prompt)
	}

	output, exitCode, err := r.runCommand(cmd)
	return output, exitCode, 0, err
}

func (r *Runner) runK8s(ctx context.Context, payload RunRequest) (string, int, int, error) {
	if r.cfg.K8sImage == "" {
		return "", -1, 0, errors.New("k8s image not configured")
	}
	manifest := r.buildJobManifest(payload)

	args := []string{"apply", "-f", "-"}
	if r.cfg.K8sNamespace != "" {
		args = append([]string{"-n", r.cfg.K8sNamespace}, args...)
	}
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stdin = strings.NewReader(manifest)
	output, exitCode, err := r.runCommand(cmd)
	return output, exitCode, 0, err
}

func (r *Runner) runCommand(cmd *exec.Cmd) (string, int, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := strings.TrimSpace(strings.TrimSuffix(stdout.String(), "\n"))
	errOut := strings.TrimSpace(strings.TrimSuffix(stderr.String(), "\n"))
	combined := strings.TrimSpace(strings.Join([]string{output, errOut}, "\n"))

	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if combined == "" {
			combined = err.Error()
		}
		return combined, exitCode, err
	}
	return combined, exitCode, nil
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
			if prompt, err := r.generatePromptFromSkill(ctx, skillPathForPrompt); err == nil && prompt != "" {
				payload.PromptInput = prompt
			} else if err != nil {
				r.log.Warn("failed to generate prompt from skill", slog.String("error", err.Error()))
			}
		}
	}

	return cleanup, nil
}

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
	return root, func() { _ = os.RemoveAll(dest) }, nil
}

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

func pickSkillRoot(dest string) string {
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return dest
	}
	return filepath.Join(dest, entries[0].Name())
}

func (r *Runner) setupClaudeCodeSkillStructure(skillPath string) (string, error) {
	// Create a temporary directory for the claude-code workspace
	tmpDir, err := os.MkdirTemp("", "claude-code-workspace-")
	if err != nil {
		return "", err
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
	// Use directory name as skill name
	if dir != "" {
		return filepath.Base(dir)
	}
	return "skill"
}

func (r *Runner) buildJobManifest(payload RunRequest) string {
	jobName := fmt.Sprintf("skill-run-%s", uuid.NewString()[:8])
	env := buildEnvMap(payload)

	// Add direct environment variables from config
	for key, value := range r.cfg.PassEnvVars {
		env[key] = value
	}

	var buf strings.Builder
	fmt.Fprintf(&buf, "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: %s\n", jobName)
	if r.cfg.K8sNamespace != "" {
		fmt.Fprintf(&buf, "  namespace: %s\n", r.cfg.K8sNamespace)
	}
	fmt.Fprintf(&buf, "spec:\n  backoffLimit: 0\n  ttlSecondsAfterFinished: %d\n  template:\n    spec:\n      restartPolicy: Never\n      containers:\n      - name: skill-runner\n        image: %s\n", r.cfg.K8sTTLSeconds, r.cfg.K8sImage)
	if len(env) > 0 {
		fmt.Fprintf(&buf, "        env:\n")
		for key, value := range env {
			fmt.Fprintf(&buf, "        - name: %s\n          value: %s\n", key, yamlQuote(value))
		}
	}
	return buf.String()
}

func buildEnv(payload RunRequest) []string {
	env := buildEnvMap(payload)
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, fmt.Sprintf("%s=%s", key, value))
	}
	return out
}

func buildEnvMap(payload RunRequest) map[string]string {
	env := map[string]string{
		"SKILL_SOURCE_TYPE":     strings.TrimSpace(payload.SourceType),
		"SKILL_SOURCE_REF":      strings.TrimSpace(payload.SourceRef),
		"SKILL_RESOLVED_REF":    strings.TrimSpace(payload.ResolvedRef),
		"SKILL_ARTIFACT_PATH":   strings.TrimSpace(payload.ArtifactPath),
		"SKILL_AGENT_TYPE":      strings.TrimSpace(payload.AgentType),
		"SKILL_RUNNER_MODE":     strings.TrimSpace(payload.RunnerMode),
		"SKILL_PROMPT_STRATEGY": strings.TrimSpace(payload.PromptStrategy),
		"SKILL_PROMPT":          strings.TrimSpace(payload.PromptInput),
	}
	for key, value := range env {
		if value == "" {
			delete(env, key)
		}
	}
	return env
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

func truncateOutput(output string, max int) string {
	trimmed := strings.TrimSpace(output)
	if max <= 0 || len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "...(truncated)"
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(payload)
}

func yamlQuote(value string) string {
	quoted, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%q", value)
	}
	return string(quoted)
}
