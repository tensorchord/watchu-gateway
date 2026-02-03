package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tensorchord/watchu/skill-runner/pkg/runner"
)

func main() {
	agentType := strings.ToUpper(strings.ReplaceAll(os.Getenv("AGENT_TYPE"), "-", "_"))
	if agentType == "" {
		agentType = "CLAUDE_CODE" // Default
	}

	cfg := runner.Config{
		Addr:             getEnv("SKILL_RUNNER_ADDR", ":8091"),
		LocalCommand:     getAgentEnv(agentType, "LOCAL_CMD", strings.TrimSpace(getEnv("SKILL_RUNNER_LOCAL_CMD", "claude"))),
		DockerImage:      getAgentEnv(agentType, "DOCKER_IMAGE", strings.TrimSpace(os.Getenv("SKILL_RUNNER_DOCKER_IMAGE"))),
		DockerCommand:    getAgentEnv(agentType, "DOCKER_COMMAND", strings.TrimSpace(os.Getenv("SKILL_RUNNER_DOCKER_COMMAND"))),
		K8sNamespace:     getEnv("SKILL_RUNNER_K8S_NAMESPACE", "default"),
		K8sImage:         strings.TrimSpace(os.Getenv("SKILL_RUNNER_K8S_IMAGE")),
		K8sTTLSeconds:    parseIntEnv("SKILL_RUNNER_K8S_TTL_SECONDS", 600),
		ExecTimeout:      parseDurationEnv("SKILL_RUNNER_EXEC_TIMEOUT", 30*time.Minute),
		LLMBaseURL:       strings.TrimSpace(os.Getenv("SKILL_RUNNER_LLM_BASE_URL")),
		LLMAPIKey:        strings.TrimSpace(os.Getenv("SKILL_RUNNER_LLM_API_KEY")),
		LLMModel:         strings.TrimSpace(getEnv("SKILL_RUNNER_LLM_MODEL", "gpt-4o")),
		LLMTimeout:       parseDurationEnv("SKILL_RUNNER_LLM_TIMEOUT", 30*time.Second),
		PassEnvVars:      getAgentPassEnvVars(agentType),
		WorkspaceBaseDir: strings.TrimSpace(os.Getenv("SKILL_RUNNER_WORKSPACE_BASE_DIR")),
		// S3 configuration for downloading artifacts
		S3Region:    strings.TrimSpace(os.Getenv("S3_REGION")),
		S3AccessKey: strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID")),
		S3SecretKey: strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY")),
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	svc := runner.New(cfg, log)

	// Start cleanup goroutine to prevent memory leaks from old run records
	cleanupMaxAge := parseDurationEnv("SKILL_RUNNER_CLEANUP_MAX_AGE", 1*time.Hour)
	svc.StartCleanup(cleanupMaxAge)
	defer svc.StopCleanup()

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      svc.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Info("skill runner listening",
		slog.String("addr", cfg.Addr),
		slog.String("agent_type", agentType),
		slog.String("docker_image", cfg.DockerImage),
		slog.String("docker_command", cfg.DockerCommand),
		slog.String("local_cmd", cfg.LocalCommand),
		slog.Int("pass_env_vars_count", len(cfg.PassEnvVars)))

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("runner stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// getAgentEnv gets agent-specific environment variable with fallback to global SKILL_RUNNER_* env
func getAgentEnv(agentType, suffix, fallback string) string {
	key := fmt.Sprintf("%s_%s", agentType, suffix)
	val := strings.TrimSpace(os.Getenv(key))
	if val != "" {
		return val
	}
	// Fallback to old SKILL_RUNNER_* env for backward compatibility
	return strings.TrimSpace(os.Getenv(fmt.Sprintf("SKILL_RUNNER_%s", suffix)))
}

// getAgentPassEnvVars gets agent-specific PASS_ENV_VARS and merges with global SKILL_RUNNER_PASS_ENV_VARS
func getAgentPassEnvVars(agentType string) map[string]string {
	// Get agent-specific pass env vars
	key := fmt.Sprintf("%s_PASS_ENV_VARS", agentType)
	agentSpecific := strings.TrimSpace(os.Getenv(key))
	var agentSpecificMap map[string]string
	if agentSpecific != "" {
		agentSpecificMap = parsePassEnvVarsString(agentSpecific)
	}

	// Get global pass env vars for backward compatibility
	global := strings.TrimSpace(os.Getenv("SKILL_RUNNER_PASS_ENV_VARS"))
	var globalMap map[string]string
	if global != "" {
		globalMap = parsePassEnvVarsString(global)
	}

	// Merge: global vars as base, agent-specific vars override
	result := make(map[string]string)
	if len(globalMap) > 0 {
		for k, v := range globalMap {
			result[k] = v
		}
	}
	if len(agentSpecificMap) > 0 {
		for k, v := range agentSpecificMap {
			result[k] = v
		}
	}
	return result
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseIntEnv(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return val
}

func parseDurationEnv(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	val, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	return val
}

// parsePassEnvVarsString parses comma-separated KEY=value pairs into a map
func parsePassEnvVarsString(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	result := make(map[string]string)
	pairs := strings.Split(raw, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" {
				result[key] = value
			}
		}
	}
	return result
}
