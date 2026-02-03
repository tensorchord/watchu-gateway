package runner

import (
	"context"
	"errors"
	"log/slog"
)

// Runtime defines the interface for executing a skill run in different environments.
type Runtime interface {
	// Execute runs the skill and returns the output, exit code, PID, and any error.
	Execute(ctx context.Context, payload RunRequest) (output string, exitCode int, pid int, err error)

	// Validate checks if the runtime is properly configured.
	Validate() error
}

// RuntimeConfig holds shared configuration for all runtime implementations.
type RuntimeConfig struct {
	Logger       *slog.Logger
	ExecTimeout  int
	PassEnvVars  map[string]string
	LLMClient    LLMClient
	LLMModel     string
}

// LLMClient is an interface for LLM completion operations.
type LLMClient interface {
	Complete(ctx context.Context, model, prompt string, temperature float64, maxTokens int) (string, error)
}

// runtimeShared provides shared utilities for runtime implementations.
type runtimeShared struct {
	cfg RuntimeConfig
}

func newRuntimeShared(cfg RuntimeConfig) *runtimeShared {
	return &runtimeShared{cfg: cfg}
}

func (s *runtimeShared) log() *slog.Logger {
	if s.cfg.Logger != nil {
		return s.cfg.Logger
	}
	return slog.Default()
}

// LocalRuntime implements Runtime for local command execution.
type LocalRuntime struct {
	shared      *runtimeShared
	localCmd    string
}

// NewLocalRuntime creates a new LocalRuntime.
func NewLocalRuntime(localCmd string, cfg RuntimeConfig) *LocalRuntime {
	return &LocalRuntime{
		shared:   newRuntimeShared(cfg),
		localCmd: localCmd,
	}
}

// Validate checks if local command is configured.
func (r *LocalRuntime) Validate() error {
	if r.localCmd == "" {
		return errors.New("local command not configured")
	}
	return nil
}

// DockerRuntime implements Runtime for Docker container execution.
type DockerRuntime struct {
	shared       *runtimeShared
	dockerImage  string
	dockerCmd    string
}

// NewDockerRuntime creates a new DockerRuntime.
func NewDockerRuntime(dockerImage, dockerCmd string, cfg RuntimeConfig) *DockerRuntime {
	return &DockerRuntime{
		shared:      newRuntimeShared(cfg),
		dockerImage: dockerImage,
		dockerCmd:   dockerCmd,
	}
}

// Validate checks if docker image is configured.
func (r *DockerRuntime) Validate() error {
	if r.dockerImage == "" {
		return errors.New("docker image not configured")
	}
	return nil
}

// K8sRuntime implements Runtime for Kubernetes Job execution.
type K8sRuntime struct {
	shared        *runtimeShared
	k8sImage      string
	k8sNamespace  string
	k8sTTLSeconds int
}

// NewK8sRuntime creates a new K8sRuntime.
func NewK8sRuntime(k8sImage, k8sNamespace string, k8sTTLSeconds int, cfg RuntimeConfig) *K8sRuntime {
	return &K8sRuntime{
		shared:        newRuntimeShared(cfg),
		k8sImage:      k8sImage,
		k8sNamespace:  k8sNamespace,
		k8sTTLSeconds: k8sTTLSeconds,
	}
}

// Validate checks if k8s image is configured.
func (r *K8sRuntime) Validate() error {
	if r.k8sImage == "" {
		return errors.New("k8s image not configured")
	}
	return nil
}
