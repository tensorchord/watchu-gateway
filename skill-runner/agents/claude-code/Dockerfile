# Claude Code Agent Docker Image
# This image provides an isolated environment for running claude-code skills
# with all necessary dependencies pre-installed.
# Using Debian (bookworm-slim) as base for Playwright compatibility

FROM node:25-bookworm-slim AS claude-installer

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code@latest

# Install Playwright globally and download browsers
# Set PLAYWRIGHT_BROWSERS_PATH to /opt/playwright for system-wide access
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN npm install -g playwright && \
    npx playwright install chromium

# Runtime stage
FROM node:25-bookworm-slim

# Set Playwright browsers path before any installation
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright

# Install development runtimes: Python, Go, Rust
# - bash: for Claude CLI shell compatibility (POSIX requirement)
# - git: for cloning skill repositories
# - curl, wget: for downloading files
# - python3 + pip: for Python code execution
# - go: for Go code execution
# - golang: Go toolchain
# - rust: Rust toolchain
# - build-essential: C/C++ compiler toolchain for native extensions
# - sudo: for running commands with elevated privileges
# - openssh-client: for git operations over SSH
# - ca-certificates, tzdata: for SSL and timezone support
# Playwright Chromium dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    python-is-python3 \
    golang-go \
    cargo \
    rustc \
    build-essential \
    sudo \
    openssh-client \
    ca-certificates \
    tzdata \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libexpat1 \
    libgbm1 \
    libgtk-3-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libpango-1.0-0 \
    libxshmfence1 \
    libasound2 \
    libatspi2.0-0 \
    libxkbcommon0 \
    && rm -rf /var/lib/apt/lists/*


# Copy Claude Code and Playwright from installer stage
COPY --from=claude-installer /usr/local/bin/claude /usr/local/bin/claude
COPY --from=claude-installer /usr/local/lib/node_modules/@anthropic-ai/claude-code /usr/local/lib/node_modules/@anthropic-ai/claude-code
COPY --from=claude-installer /opt/playwright /opt/playwright

# Create a non-root user for running skills
# UID=100, GID=101 must match the hardcoded values in pkg/runner/runner.go
# Handle potential existing UID/GID by removing them first
RUN (groupadd -g 101 claude 2>/dev/null || groupadd -g 101 -o claude) && \
    (useradd -M -u 100 -g claude -d /home/claude -s /bin/bash claude 2>/dev/null || \
     (EXISTING_USER=$(getent passwd 100 | cut -d: -f1); userdel "$EXISTING_USER" 2>/dev/null; \
      useradd -m -u 100 -g claude -d /home/claude -s /bin/bash claude)) && \
    usermod -aG sudo claude && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/claude && \
    chmod 440 /etc/sudoers.d/claude && \
    mkdir -p /home/claude/.claude/skills && \
    chown -R claude:claude /home/claude/.claude && \
    chmod -R 755 /opt/playwright

# Set up working directory for skills
WORKDIR /skill

# Switch to non-root user
USER claude

# Default to bash for interactive sessions
SHELL ["/bin/bash", "-c"]

# Set environment variables
ENV NODE_ENV=production \
    PATH="/usr/local/bin:/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin:${PATH}" \
    HOME=/home/claude \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright \
    PIP_BREAK_SYSTEM_PACKAGES=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD claude --version || exit 1

# No ENTRYPOINT/CMD - let runner specify the full command
# This allows flexibility: SKILL_RUNNER_DOCKER_COMMAND can be any command
# Example: "claude --dangerously-skip-permissions --output-format stream-json --verbose -p"
