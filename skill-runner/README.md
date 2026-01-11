# Skill Runner

HTTP service that executes claude-code skills in local, Docker, or Kubernetes modes.

## Development

### Prerequisites

- Go 1.22+
- Docker (for Docker runner mode)
- Node.js 20+ (for local claude-code)
- kubectl (for Kubernetes runner mode, optional)

### Build and Run

```bash
# Build the runner binary
make build

# Run the runner service (listens on :8091)
make run

# Run with custom local command
SKILL_RUNNER_LOCAL_CMD="/path/to/claude" make run
```

### Build Agent Docker Image

The claude-code agent Docker image provides an isolated environment for running skills:

```bash
# List available agents
make list-agents

# Build the claude-code agent (default)
make build-agent

# Build a specific agent
make build-agent AGENT=claude-code

# Build with local tag for testing
make build-agent-local

# Build with custom tag
IMAGE_TAG=v1.0.0 make build-agent

# Push to registry
IMAGE_TAG=v1.0.0 make push-agent
```

The agent image includes:
- Claude Code CLI (@anthropic-ai/claude-code)
- Node.js 20 runtime
- Common development tools (git, python3, curl, wget, bash)
- Non-root user for security

### Testing

```bash
# Run Go tests
make test

# Run tests with coverage
make test-coverage

# Test with Docker runner mode
make run-agent-docker
```

### Makefile Targets

```bash
make help           # Show all available targets
make build          # Build skill-runner binary
make build-agent    # Build agent Docker image (use AGENT=name)
make push-agent     # Push agent image to registry
make list-agents    # List available agents
make run            # Run skill-runner service
make test           # Run tests
make clean          # Clean build artifacts
```

## Quick Start (Local)

```bash
cd skill-runner
go run ./cmd/runner
```

The runner listens on `:8091` by default. To point the gateway at the local runner:

```bash
export SKILL_RUNNER_BASE_URL=http://host.docker.internal:8091
```

If you're running the gateway on the host (not in Docker), use:

```bash
export SKILL_RUNNER_BASE_URL=http://127.0.0.1:8091
```

### Local Command for Claude Code

For claude-code, set the local command to include the necessary flags:

```bash
export SKILL_RUNNER_LOCAL_CMD="claude --dangerously-skip-permissions --output-format stream-json --verbose -p"
```

This ensures claude-code runs with:
- `--dangerously-skip-permissions`: Skip permission prompts for automated execution
- `--output-format stream-json`: Output in streaming JSON format
- `--verbose`: Enable verbose logging
- `-p`: Read prompt from stdin (used by the runner)

## Docker Runner

The Docker runner executes skills in an isolated Docker container with the skill directory mounted as a read-only volume.

### Building the Agent Image

First, build the claude-code agent Docker image:

```bash
cd skill-runner
make build-agent
```

This builds the `ghcr.io/tensorchord/watchu-claude-code-agent:latest` image.

### Setup

1. Set the Docker image and command:

```bash
export SKILL_RUNNER_DOCKER_IMAGE="ghcr.io/tensorchord/watchu-claude-code-agent:latest"
export SKILL_RUNNER_DOCKER_COMMAND="claude --dangerously-skip-permissions --output-format stream-json --verbose -p"
```

The Docker image has no ENTRYPOINT/CMD, so the full command must be specified.

2. The runner will automatically:
   - Mount the uploaded skill directory to `/skill` (read-only)
   - Set the working directory to `/skill`
   - Pass environment variables with skill metadata
   - Pass through Claude Code environment variables (see Environment Variables below)
   - Execute the command in the container

### How It Works

When a skill is executed in Docker mode, the runner:

1. Prepares the skill artifact (extracts archives if needed)
2. Mounts the skill directory as a read-only volume:
   ```
   -v /tmp/skill-upload-xxx:/skill:ro
   ```
3. Sets the working directory:
   ```
   -w /skill
   ```
4. Passes environment variables:
   ```
   -e SKILL_SOURCE_TYPE=upload
   -e SKILL_SOURCE_REF=my-skill
   -e SKILL_ARTIFACT_PATH=/skill
   -e SKILL_PROMPT="..."
   -e ANTHROPIC_BASE_URL=...
   -e ANTHROPIC_AUTH_TOKEN=...
   # ... other ANTHROPIC_, CLAUDE_, API_* variables
   ```
5. Executes the command:
   ```bash
   docker run --rm \
     -v /tmp/skill-upload-xxx:/skill:ro \
     -w /skill \
     -e SKILL_PROMPT="..." \
     -e ANTHROPIC_BASE_URL="..." \
     -e ANTHROPIC_AUTH_TOKEN="..." \
     ghcr.io/tensorchord/watchu-claude-code-agent:latest \
     claude --dangerously-skip-permissions --output-format stream-json --verbose -p
   ```

### Example Configuration

Complete example with direct environment variables:

```bash
# Docker runner settings
export SKILL_RUNNER_DOCKER_IMAGE="ghcr.io/tensorchord/watchu-claude-code-agent:latest"
export SKILL_RUNNER_DOCKER_COMMAND="claude --dangerously-skip-permissions --output-format stream-json --verbose -p"

# Pass Claude Code configuration directly (recommended)
export SKILL_RUNNER_PASS_ENV_VARS="ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic,ANTHROPIC_AUTH_TOKEN=your-api-key,ANTHROPIC_DEFAULT_OPUS_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_SONNET_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_HAIKU_MODEL=GLM-4.5-Air,API_TIMEOUT_MS=3000000,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"

# Optional: LLM for prompt generation
export SKILL_RUNNER_LLM_BASE_URL="http://127.0.0.1:4000"
export SKILL_RUNNER_LLM_API_KEY="dummy"

# Execution timeout (optional, default 30m)
export SKILL_RUNNER_EXEC_TIMEOUT="10m"

# Run the service
./skill-runner
```

Or use a script for convenience:

```bash
#!/bin/bash
export SKILL_RUNNER_DOCKER_IMAGE="ghcr.io/tensorchord/watchu-claude-code-agent:latest"
export SKILL_RUNNER_DOCKER_COMMAND="claude --dangerously-skip-permissions --output-format stream-json --verbose -p"
export SKILL_RUNNER_PASS_ENV_VARS="ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic,ANTHROPIC_AUTH_TOKEN=your-key,API_TIMEOUT_MS=3000000,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1,ANTHROPIC_DEFAULT_OPUS_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_SONNET_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_HAIKU_MODEL=GLM-4.5-Air"
./skill-runner
```

## Kubernetes Runner

The Kubernetes runner creates a one-time Job to execute the skill in a Kubernetes pod.

### Setup

1. Build and push the agent image (see "Build Agent Docker Image" above)

2. Set the Kubernetes image and namespace:

```bash
export SKILL_RUNNER_K8S_IMAGE="ghcr.io/tensorchord/watchu-claude-code-agent:latest"
export SKILL_RUNNER_K8S_NAMESPACE="default"
```

3. The runner will automatically:
   - Create a Job manifest with the skill image
   - Set resource cleanup (TTL) after completion
   - Pass environment variables with skill metadata
   - Submit the Job to the Kubernetes cluster

### How It Works

When a skill is executed in Kubernetes mode, the runner:

1. Generates a unique Job name: `skill-run-<uuid>`
2. Creates a Job manifest with:
   - `restartPolicy: Never`
   - `backoffLimit: 0`
   - TTL for automatic cleanup
   - Environment variables
3. Applies the manifest using `kubectl`:
   ```bash
   kubectl apply -f - <<EOF
   apiVersion: batch/v1
   kind: Job
   metadata:
     name: skill-run-abc123
     namespace: default
   spec:
     backoffLimit: 0
     ttlSecondsAfterFinished: 600
     template:
       spec:
         restartPolicy: Never
         containers:
         - name: skill-runner
           image: ghcr.io/tensorchord/watchu-claude-code-agent:latest
           env:
           - name: SKILL_PROMPT
             value: "..."
   EOF
   ```

### Example Configuration

```bash
# Kubernetes runner settings
export SKILL_RUNNER_K8S_IMAGE="ghcr.io/tensorchord/watchu-claude-code-agent:latest"
export SKILL_RUNNER_K8S_NAMESPACE="skills"

# Claude Code API configuration (automatically passed through)
export ANTHROPIC_BASE_URL="https://open.bigmodel.cn/api/anthropic"
export ANTHROPIC_AUTH_TOKEN="your-api-key"
export ANTHROPIC_DEFAULT_OPUS_MODEL="GLM-4.7"
export ANTHROPIC_DEFAULT_SONNET_MODEL="GLM-4.7"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="GLM-4.5-Air"
export API_TIMEOUT_MS="3000000"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"

# Job TTL in seconds (optional, default 600)
export SKILL_RUNNER_K8S_TTL_SECONDS="3600"

# Execution timeout (optional, default 30m)
export SKILL_RUNNER_EXEC_TIMEOUT="10m"
```

### Monitoring Job Status

The runner returns immediately after creating the Job. To monitor execution:

```bash
# List jobs
kubectl get jobs -n skills

# View job logs
kubectl logs -n skills job/skill-run-abc123

# Check job status
kubectl describe job -n skills skill-run-abc123
```

## Environment Variables

### Runner Configuration

- `SKILL_RUNNER_ADDR` (default `:8091`)
- `SKILL_RUNNER_LOCAL_CMD` (default `claude`)
- `SKILL_RUNNER_DOCKER_IMAGE`
- `SKILL_RUNNER_DOCKER_COMMAND`
- `SKILL_RUNNER_K8S_NAMESPACE` (default `default`)
- `SKILL_RUNNER_K8S_IMAGE`
- `SKILL_RUNNER_K8S_TTL_SECONDS` (default `600`)
- `SKILL_RUNNER_EXEC_TIMEOUT` (default `30m`)

### Environment Variable Passthrough

Use `SKILL_RUNNER_PASS_ENV_VARS` to pass environment variables to Docker/K8s containers as comma-separated `KEY=value` pairs:

```bash
export SKILL_RUNNER_PASS_ENV_VARS="ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic,ANTHROPIC_AUTH_TOKEN=your-key,API_TIMEOUT_MS=3000000,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1,ANTHROPIC_DEFAULT_OPUS_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_SONNET_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_HAIKU_MODEL=GLM-4.5-Air"
```

This method is reliable and explicit, working consistently across different execution contexts.

### LLM Configuration (for Prompt Generation)

When using `prompt_strategy: "from-skill"`, the runner uses an LLM to analyze the SKILL.md file and generate an appropriate user prompt to trigger the skill.

- `SKILL_RUNNER_LLM_BASE_URL` — OpenAI-compatible API endpoint (e.g., `https://api.openai.com/v1`)
- `SKILL_RUNNER_LLM_API_KEY` — API key for the LLM service
- `SKILL_RUNNER_LLM_MODEL` (default `gpt-4o`) — Model to use for prompt generation
- `SKILL_RUNNER_LLM_TIMEOUT` (default `30s`) — Request timeout

If the LLM client is not configured, the runner falls back to a simple template prompt.

## Endpoints

- `POST /run` — start a run
- `GET /runs/{id}` — get run status
- `GET /health`

## Notes

- Runner injects skill metadata into environment variables (e.g. `SKILL_SOURCE_REF`, `SKILL_PROMPT`).
- For Docker/K8s, mount or bake in the skill artifact; `SKILL_ARTIFACT_PATH` is passed through.
- When `prompt_strategy` is `from-skill`, the runner reads `SKILL.md` and uses LLM to generate a test prompt.
- When `prompt_strategy` is `custom`, the runner uses the provided `prompt_input` directly.
