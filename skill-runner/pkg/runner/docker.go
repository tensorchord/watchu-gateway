package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Execute runs the skill using Docker container execution.
func (r *DockerRuntime) Execute(ctx context.Context, payload RunRequest) (string, int, int, error) {
	args := []string{"run", "--rm"}

	// Force running as non-root user (uid=100 for claude user) to satisfy
	// Claude Code CLI's security requirement: --dangerously-skip-permissions
	// cannot be used with root/sudo privileges
	// The claude user in the agent image has uid=100, gid=101
	args = append(args, "--user=100:101")

	// Check if we need stdin (for prompt input)
	prompt := strings.TrimSpace(payload.PromptInput)
	needsStdin := prompt != "" && strings.Contains(r.dockerCmd, "-p")

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
	for key, value := range r.shared.cfg.PassEnvVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	args = append(args, r.dockerImage)
	if strings.TrimSpace(r.dockerCmd) != "" {
		args = append(args, strings.Fields(r.dockerCmd)...)
	}

	r.shared.log().Info("docker command built",
		"env_direct_count", len(r.shared.cfg.PassEnvVars),
		"command", "docker "+strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, "docker", args...)

	// Set stdin if prompt is available
	if needsStdin {
		cmd.Stdin = strings.NewReader(prompt)
	}

	output, exitCode, err := r.runCommand(cmd)
	return output, exitCode, 0, err
}

// runCommand executes a command and returns its output.
func (r *DockerRuntime) runCommand(cmd *exec.Cmd) (string, int, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	r.shared.log().Debug("executing command",
		"path", cmd.Path,
		"args_count", len(cmd.Args),
		"has_stdin", cmd.Stdin != nil)

	err := cmd.Run()
	output := strings.TrimSpace(strings.TrimSuffix(stdout.String(), "\n"))
	errOut := strings.TrimSpace(strings.TrimSuffix(stderr.String(), "\n"))
	combined := strings.TrimSpace(strings.Join([]string{output, errOut}, "\n"))

	r.shared.log().Debug("command completed",
		"stdout_len", len(output),
		"stderr_len", len(errOut),
		"stderr_preview", func() string {
			if len(errOut) > 200 {
				return errOut[:200] + "..."
			}
			return errOut
		}(),
		"has_error", err != nil)

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
