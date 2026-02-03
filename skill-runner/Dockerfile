FROM golang:1.24-alpine AS builder
ENV GOPROXY=https://goproxy.cn,direct
ENV GOTOOLCHAIN=auto
WORKDIR /app

# Download dependencies first (cached unless go.mod/go.sum change)
COPY gateway/go.mod gateway/go.sum ./gateway/
COPY skill-runner/go.mod skill-runner/go.sum ./skill-runner/
RUN cd gateway && go mod download
RUN cd skill-runner && go mod download

# Then copy source code
COPY gateway ./gateway
COPY skill-runner ./skill-runner
WORKDIR /app/skill-runner
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/skill-runner ./cmd/runner

FROM alpine:3.19

# Install essential development tools and runtimes for Claude CLI to execute code
# - Docker CLI: for Docker-outside-of-Docker (DooD)
# - Python3 + pip: for Python code execution
# - Node.js + npm: for JavaScript/TypeScript code execution and claude CLI
# - git: for cloning skill repositories
# - bash: for Claude CLI shell compatibility (POSIX requirement)
# - build-base: C/C++ compiler toolchain (gcc, g++, make)
# - curl, wget: for downloading files
# - jq: for JSON processing
RUN apk add --no-cache \
    docker-cli \
    python3 \
    py3-pip \
    nodejs \
    npm \
    git \
    bash \
    build-base \
    curl \
    wget \
    jq

# Install common Python packages for data science and general use
RUN pip3 install --no-cache-dir --break-system-packages \
    numpy \
    pandas \
    requests \
    matplotlib \
    beautifulsoup4 \
    pyyaml

# Install claude CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Install su-exec for switching users
RUN apk add --no-cache su-exec

# Ensure Claude CLI can find a POSIX shell
ENV SHELL=/bin/bash
ENV PATH="/usr/local/bin:$PATH"

# Copy entrypoint script
COPY skill-runner/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy skill-runner binary from builder
COPY --from=builder /bin/skill-runner /usr/local/bin/skill-runner

EXPOSE 8091
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
