package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Config struct {
	Addr                  string
	LocalCommand          string
	LocalArgs             []string
	DockerCommand         string
	DockerImage           string
	DockerArgs            []string
	DockerEntrypoint      string
	DockerCommandOverride []string
	K8sCommand            string
	K8sNamespace          string
	K8sImage              string
	K8sTTLSeconds         int
	K8sCPU                string
	K8sMemory             string
	K8sCommandOverride    []string
	ExecTimeout           time.Duration
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
	RunID      string `json:"run_id"`
	Status     string `json:"status"`
	RootExecID string `json:"root_exec_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

type RunRecord struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	RootExecID string    `json:"root_exec_id,omitempty"`
	Error      string    `json:"error,omitempty"`
	Mode       string    `json:"runner_mode"`
	Output     string    `json:"output,omitempty"`
	ExitCode   int       `json:"exit_code,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at,omitempty"`
}

type Runner struct {
	cfg  Config
	log  *slog.Logger
	mu   sync.RWMutex
	runs map[string]*RunRecord
	re   *regexp.Regexp
}

func New(cfg Config, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		cfg:  cfg,
		log:  logger,
		runs: make(map[string]*RunRecord),
		re:   regexp.MustCompile(`(?i)root[_-]?exec[_-]?id["'\s:=]+([a-f0-9-]{16,})`),
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
	var execErr error

	switch mode {
	case "local":
		output, exitCode, execErr = r.runLocal(ctx, payload)
	case "docker":
		output, exitCode, execErr = r.runDocker(ctx, payload)
	case "k8s":
		output, exitCode, execErr = r.runK8s(ctx, payload)
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
		record.RootExecID = rootExecID
		record.EndedAt = time.Now().UTC()
		if execErr != nil {
			record.Error = execErr.Error()
		}
	}
	r.mu.Unlock()

	if execErr != nil {
		r.log.Error("run failed", slog.String("run_id", runID), slog.String("error", execErr.Error()))
	}
}

func (r *Runner) runLocal(ctx context.Context, payload RunRequest) (string, int, error) {
	if r.cfg.LocalCommand == "" {
		return "", -1, errors.New("local command not configured")
	}
	args := append([]string{}, r.cfg.LocalArgs...)
	cmd := exec.CommandContext(ctx, r.cfg.LocalCommand, args...)
	cmd.Env = append(os.Environ(), buildEnv(payload)...)
	if payload.ArtifactPath != "" {
		cmd.Dir = payload.ArtifactPath
	}
	if payload.PromptInput != "" {
		cmd.Stdin = strings.NewReader(payload.PromptInput)
	}
	return r.runCommand(cmd)
}

func (r *Runner) runDocker(ctx context.Context, payload RunRequest) (string, int, error) {
	if r.cfg.DockerCommand == "" {
		return "", -1, errors.New("docker command not configured")
	}
	if r.cfg.DockerImage == "" {
		return "", -1, errors.New("docker image not configured")
	}

	args := []string{"run", "--rm"}
	if r.cfg.DockerEntrypoint != "" {
		args = append(args, "--entrypoint", r.cfg.DockerEntrypoint)
	}
	if payload.ArtifactPath != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/skill", payload.ArtifactPath), "-w", "/skill")
	}
	for _, env := range buildEnv(payload) {
		args = append(args, "-e", env)
	}
	args = append(args, r.cfg.DockerArgs...)
	args = append(args, r.cfg.DockerImage)
	args = append(args, r.cfg.DockerCommandOverride...)

	cmd := exec.CommandContext(ctx, r.cfg.DockerCommand, args...)
	return r.runCommand(cmd)
}

func (r *Runner) runK8s(ctx context.Context, payload RunRequest) (string, int, error) {
	if r.cfg.K8sCommand == "" {
		return "", -1, errors.New("kubectl command not configured")
	}
	if r.cfg.K8sImage == "" {
		return "", -1, errors.New("k8s image not configured")
	}
	manifest := r.buildJobManifest(payload)

	args := []string{"apply", "-f", "-"}
	if r.cfg.K8sNamespace != "" {
		args = append([]string{"-n", r.cfg.K8sNamespace}, args...)
	}
	cmd := exec.CommandContext(ctx, r.cfg.K8sCommand, args...)
	cmd.Stdin = strings.NewReader(manifest)
	return r.runCommand(cmd)
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

func (r *Runner) buildJobManifest(payload RunRequest) string {
	jobName := fmt.Sprintf("skill-run-%s", uuid.NewString()[:8])
	env := buildEnvMap(payload)

	var buf strings.Builder
	fmt.Fprintf(&buf, "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: %s\n", jobName)
	if r.cfg.K8sNamespace != "" {
		fmt.Fprintf(&buf, "  namespace: %s\n", r.cfg.K8sNamespace)
	}
	fmt.Fprintf(&buf, "spec:\n  backoffLimit: 0\n  ttlSecondsAfterFinished: %d\n  template:\n    spec:\n      restartPolicy: Never\n      containers:\n      - name: skill-runner\n        image: %s\n", r.cfg.K8sTTLSeconds, r.cfg.K8sImage)
	if len(r.cfg.K8sCommandOverride) > 0 {
		fmt.Fprintf(&buf, "        command:\n")
		for _, cmd := range r.cfg.K8sCommandOverride {
			fmt.Fprintf(&buf, "        - %s\n", yamlQuote(cmd))
		}
	}
	if r.cfg.K8sCPU != "" || r.cfg.K8sMemory != "" {
		fmt.Fprintf(&buf, "        resources:\n")
		fmt.Fprintf(&buf, "          requests:\n")
		if r.cfg.K8sCPU != "" {
			fmt.Fprintf(&buf, "            cpu: %s\n", yamlQuote(r.cfg.K8sCPU))
		}
		if r.cfg.K8sMemory != "" {
			fmt.Fprintf(&buf, "            memory: %s\n", yamlQuote(r.cfg.K8sMemory))
		}
		fmt.Fprintf(&buf, "          limits:\n")
		if r.cfg.K8sCPU != "" {
			fmt.Fprintf(&buf, "            cpu: %s\n", yamlQuote(r.cfg.K8sCPU))
		}
		if r.cfg.K8sMemory != "" {
			fmt.Fprintf(&buf, "            memory: %s\n", yamlQuote(r.cfg.K8sMemory))
		}
	}
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
