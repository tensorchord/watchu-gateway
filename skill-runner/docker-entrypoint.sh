#!/bin/sh
set -e

# Ensure workspace directory exists with correct permissions
mkdir -p /tmp/watchu-skill-workspaces
chmod 1777 /tmp/watchu-skill-workspaces

# Create non-root user and group if they don't exist
if ! getent group claude >/dev/null 2>&1; then
    addgroup -g 101 claude
fi
if ! getent passwd claude >/dev/null 2>&1; then
    adduser -D -u 100 -G claude claude
fi

# Add user to docker group if DOCKER_GID is set
# DOCKER_GID should match the host's docker group GID (getent group docker | cut -d: -f3)
if [ -n "$DOCKER_GID" ]; then
    if ! getent group docker >/dev/null 2>&1; then
        addgroup -g "$DOCKER_GID" docker
    fi
    addgroup claude docker 2>/dev/null || true
fi

# Ensure POSIX shell is available for CLI tools
export SHELL="${SHELL:-/bin/bash}"

# Switch to non-root user and run the command
exec su-exec claude "$@"
