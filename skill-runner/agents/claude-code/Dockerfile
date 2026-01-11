# Claude Code Agent Docker Image
# This image provides an isolated environment for running claude-code skills
# with all necessary dependencies pre-installed.

FROM node:20-alpine AS claude-installer

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code@latest

# Runtime stage
FROM node:20-alpine

# Install common development tools that skills might need
RUN apk add --no-cache \
    bash \
    git \
    curl \
    wget \
    python3 \
    py3-pip \
    openssh-client \
    ca-certificates \
    tzdata

# Copy Claude Code from installer stage
COPY --from=claude-installer /usr/local/bin/claude /usr/local/bin/claude
COPY --from=claude-installer /usr/local/lib/node_modules/@anthropic-ai/claude-code /usr/local/lib/node_modules/@anthropic-ai/claude-code

# Create a non-root user for running skills
RUN addgroup -S claude && \
    adduser -S claude -G claude -h /home/claude && \
    mkdir -p /home/claude/.claude/skills && \
    chown -R claude:claude /home/claude/.claude

# Set up working directory for skills
WORKDIR /skill

# Switch to non-root user
USER claude

# Default to bash for interactive sessions
SHELL ["/bin/bash", "-c"]

# Set environment variables
ENV NODE_ENV=production \
    PATH="/usr/local/bin:/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin:${PATH}" \
    HOME=/home/claude

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD claude --version || exit 1

# No ENTRYPOINT/CMD - let runner specify the full command
# This allows flexibility: SKILL_RUNNER_DOCKER_COMMAND can be any command
# Example: "claude --dangerously-skip-permissions --output-format stream-json --verbose -p"
