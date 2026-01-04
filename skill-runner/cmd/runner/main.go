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
		Addr:                  getEnv("SKILL_RUNNER_ADDR", ":8091"),
		LocalCommand:          getEnv("SKILL_RUNNER_LOCAL_CMD", "claude-code"),
		LocalArgs:             strings.Fields(os.Getenv("SKILL_RUNNER_LOCAL_ARGS")),
		DockerCommand:         getEnv("SKILL_RUNNER_DOCKER_CMD", "docker"),
		DockerImage:           strings.TrimSpace(os.Getenv("SKILL_RUNNER_DOCKER_IMAGE")),
		DockerArgs:            strings.Fields(os.Getenv("SKILL_RUNNER_DOCKER_ARGS")),
		DockerEntrypoint:      strings.TrimSpace(os.Getenv("SKILL_RUNNER_DOCKER_ENTRYPOINT")),
		DockerCommandOverride: strings.Fields(os.Getenv("SKILL_RUNNER_DOCKER_COMMAND")),
		K8sCommand:            getEnv("SKILL_RUNNER_K8S_CMD", "kubectl"),
		K8sNamespace:          getEnv("SKILL_RUNNER_K8S_NAMESPACE", "default"),
		K8sImage:              strings.TrimSpace(os.Getenv("SKILL_RUNNER_K8S_IMAGE")),
		K8sTTLSeconds:         parseIntEnv("SKILL_RUNNER_K8S_TTL_SECONDS", 600),
		K8sCPU:                strings.TrimSpace(os.Getenv("SKILL_RUNNER_K8S_CPU")),
		K8sMemory:             strings.TrimSpace(os.Getenv("SKILL_RUNNER_K8S_MEMORY")),
		K8sCommandOverride:    strings.Fields(os.Getenv("SKILL_RUNNER_K8S_COMMAND")),
		ExecTimeout:           parseDurationEnv("SKILL_RUNNER_EXEC_TIMEOUT", 30*time.Minute),
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	svc := runner.New(cfg, log)

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      svc.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Info("skill runner listening", slog.String("addr", cfg.Addr))
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
