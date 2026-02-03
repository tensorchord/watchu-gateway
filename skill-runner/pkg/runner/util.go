package runner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// buildEnv builds a list of environment variables from the run request.
func buildEnv(payload RunRequest) []string {
	env := buildEnvMap(payload)
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, fmt.Sprintf("%s=%s", key, value))
	}
	return out
}

// buildEnvMap builds a map of environment variables from the run request.
func buildEnvMap(payload RunRequest) map[string]string {
	env := map[string]string{
		"SKILL_SOURCE_TYPE":     strings.TrimSpace(payload.SourceType),
		"SKILL_SOURCE_REF":      strings.TrimSpace(payload.SourceRef),
		"SKILL_NAME":            strings.TrimSpace(payload.SkillName),
		"SKILL_RESOLVED_REF":    strings.TrimSpace(payload.ResolvedRef),
		"SKILL_ARTIFACT_PATH":   strings.TrimSpace(payload.ArtifactPath),
		"SKILL_AGENT_TYPE":      strings.TrimSpace(payload.AgentType),
		"SKILL_RUNNER_MODE":     strings.TrimSpace(payload.RunnerMode),
		"SKILL_PROMPT_STRATEGY": strings.TrimSpace(payload.PromptStrategy),
		"SKILL_PROMPT":          strings.TrimSpace(payload.PromptInput),
		"SHELL":                 "/bin/bash", // Claude CLI requires a POSIX-compliant shell
		"WATCHU_CORRELATION_ID": strings.TrimSpace(payload.AnalysisID),
	}
	for key, value := range env {
		if value == "" {
			delete(env, key)
		}
	}
	return env
}

// truncateOutput truncates output to a maximum length.
func truncateOutput(output string, max int) string {
	trimmed := strings.TrimSpace(output)
	if max <= 0 || len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "...(truncated)"
}

// respondJSON writes a JSON response to the HTTP response writer.
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(payload)
}

// yamlQuote quotes a string for YAML output.
func yamlQuote(value string) string {
	quoted, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%q", value)
	}
	return string(quoted)
}
