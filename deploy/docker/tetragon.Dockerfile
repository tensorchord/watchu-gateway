# Dockerfile for building Tetragon with environment variable support
# Uses the latest main branch which includes --filter-environment-variables
# This simplified version uses Tetragon's official build process

FROM golang:1.25-bookworm AS builder

WORKDIR /go/src/github.com/cilium/tetragon

# Install build dependencies
RUN apt-get update && apt-get install -y \
    make \
    git \
    clang \
    llvm \
    gcc \
    libc6-dev \
    libelf-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone Tetragon from main branch with environment variable support
RUN git clone https://github.com/cilium/tetragon.git . && \
    git log --oneline -1 && \
    echo "Building Tetragon with environment variable support..."

# Build BPF programs first
RUN make tetragon-bpf LOCAL_CLANG=1

# Build Tetragon binaries
RUN make tetragon tetra

# Final runtime stage based on Alpine (same as official Tetragon)
FROM alpine:3.23

# Install runtime dependencies
RUN apk add --no-cache \
    bash \
    iproute2 \
    ca-certificates

# Create necessary directories
RUN mkdir -p /var/lib/tetragon /var/run/tetragon /etc/tetragon/tetragon.tp.d /etc/tetragon/tetragon.conf.d

# Copy binaries and BPF objects from builder
COPY --from=builder /go/src/github.com/cilium/tetragon/tetragon /usr/bin/tetragon
COPY --from=builder /go/src/github.com/cilium/tetragon/tetra /usr/bin/tetra
COPY --from=builder /go/src/github.com/cilium/tetragon/bpf/objs/*.o /var/lib/tetragon/

# Verify the binaries have environment variable support
RUN /usr/bin/tetragon --help 2>&1 | grep -q "enable-process-environment-variables" && \
    echo "✅ Environment variable support verified"

VOLUME ["/var/lib/tetragon", "/var/run/tetragon"]

ENTRYPOINT ["/usr/bin/tetragon"]

LABEL org.opencontainers.image.source="https://github.com/cilium/tetragon"
LABEL org.opencontainers.image.description="Tetragon with environment variable filtering support (main branch)"
