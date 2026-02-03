package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Execute runs the skill using local command execution in a detached process.
func (r *LocalRuntime) Execute(ctx context.Context, payload RunRequest) (string, int, int, error) {
	cmd, args, err := splitCommand(r.localCmd)
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

	// Build complete environment list (skill env vars + PassEnvVars)
	envVars := buildEnv(payload)
	for key, value := range r.shared.cfg.PassEnvVars {
		envVars = append(envVars, fmt.Sprintf("%s=%s", key, value))
	}

	script := r.buildDetachedScript(workdir, cmd, args, promptPath, outputPath, exitPath, pidPath, envVars, payload.AnalysisID)
	r.shared.log().Info("generated run script",
		"script", script,
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

	r.shared.log().Info("local run detached",
		"output_path", outputPath,
		"exit_path", exitPath,
		"pid", pid,
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

// buildDetachedScript generates the shell script for detached local execution.
func (r *LocalRuntime) buildDetachedScript(workdir, cmd string, args []string, promptPath, outputPath, exitPath, pidPath string, envVars []string, correlationID string) string {
	var builder strings.Builder
	builder.WriteString("#!/bin/sh\n")
	// Export environment variables
	for _, env := range envVars {
		builder.WriteString("export ")
		builder.WriteString(shellQuote(env))
		builder.WriteString("\n")
	}
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

// splitCommand splits a command string into command and arguments.
func splitCommand(command string) (string, []string, error) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "", nil, errors.New("local command not configured")
	}
	return fields[0], fields[1:], nil
}

// readExitCode reads an exit code from a file.
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
