package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"
)

// Execute runs the skill using Kubernetes Job execution.
func (r *K8sRuntime) Execute(ctx context.Context, payload RunRequest) (string, int, int, error) {
	manifest := r.buildJobManifest(payload)

	args := []string{"apply", "-f", "-"}
	if r.k8sNamespace != "" {
		args = append([]string{"-n", r.k8sNamespace}, args...)
	}
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stdin = strings.NewReader(manifest)
	output, exitCode, err := r.runCommand(cmd)
	return output, exitCode, 0, err
}

// buildJobManifest generates the Kubernetes Job YAML manifest.
func (r *K8sRuntime) buildJobManifest(payload RunRequest) string {
	jobName := fmt.Sprintf("skill-run-%s", uuid.NewString()[:8])
	env := buildEnvMap(payload)

	// Add direct environment variables from config
	for key, value := range r.shared.cfg.PassEnvVars {
		env[key] = value
	}

	var buf strings.Builder
	fmt.Fprintf(&buf, "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: %s\n", jobName)
	if r.k8sNamespace != "" {
		fmt.Fprintf(&buf, "  namespace: %s\n", r.k8sNamespace)
	}
	fmt.Fprintf(&buf, "spec:\n  backoffLimit: 0\n  ttlSecondsAfterFinished: %d\n  template:\n    spec:\n      restartPolicy: Never\n      containers:\n      - name: skill-runner\n        image: %s\n", r.k8sTTLSeconds, r.k8sImage)
	if len(env) > 0 {
		fmt.Fprintf(&buf, "        env:\n")
		for key, value := range env {
			fmt.Fprintf(&buf, "        - name: %s\n          value: %s\n", key, yamlQuote(value))
		}
	}
	return buf.String()
}

// runCommand executes a command and returns its output.
func (r *K8sRuntime) runCommand(cmd *exec.Cmd) (string, int, error) {
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
