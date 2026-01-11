package main

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tensorchord/watchu/skill-runner/pkg/runner"
)

func main() {
	cfg := runner.Config{
		Addr:          getEnv("SKILL_RUNNER_ADDR", ":8091"),
		LocalCommand:  strings.TrimSpace(getEnv("SKILL_RUNNER_LOCAL_CMD", "claude")),
		DockerImage:   strings.TrimSpace(os.Getenv("SKILL_RUNNER_DOCKER_IMAGE")),
		DockerCommand: strings.TrimSpace(os.Getenv("SKILL_RUNNER_DOCKER_COMMAND")),
		K8sNamespace:  getEnv("SKILL_RUNNER_K8S_NAMESPACE", "default"),
		K8sImage:      strings.TrimSpace(os.Getenv("SKILL_RUNNER_K8S_IMAGE")),
		K8sTTLSeconds: parseIntEnv("SKILL_RUNNER_K8S_TTL_SECONDS", 600),
		ExecTimeout:   parseDurationEnv("SKILL_RUNNER_EXEC_TIMEOUT", 30*time.Minute),
		LLMBaseURL:    strings.TrimSpace(os.Getenv("SKILL_RUNNER_LLM_BASE_URL")),
		LLMAPIKey:     strings.TrimSpace(os.Getenv("SKILL_RUNNER_LLM_API_KEY")),
		LLMModel:      strings.TrimSpace(getEnv("SKILL_RUNNER_LLM_MODEL", "gpt-4o")),
		LLMTimeout:    parseDurationEnv("SKILL_RUNNER_LLM_TIMEOUT", 30*time.Second),
		PassEnvVars:   getPassEnvVars(),
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	svc := runner.New(cfg, log)

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      svc.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Info("skill runner listening",
		slog.String("addr", cfg.Addr),
		slog.Int("pass_env_vars_count", len(cfg.PassEnvVars)))

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("runner stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
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

// getPassEnvVars reads environment variables from SKILL_RUNNER_PASS_ENV_VARS
// Format: KEY1=value1,KEY2=value2,KEY3=value3
func getPassEnvVars() map[string]string {
	raw := os.Getenv("SKILL_RUNNER_PASS_ENV_VARS")
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
