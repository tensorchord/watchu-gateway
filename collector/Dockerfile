# this is only for amd64
FROM ghcr.io/tensorchord/ebpf-builder:0.1.2 AS builder

WORKDIR /workspace
ENV GOPROXY=https://goproxy.cn,direct
ENV GOSUMDB=sum.golang.google.cn
ENV GO111MODULE=on

COPY . .

# Use Makefile build (includes go generate for eBPF artifacts).
RUN set -eux; \
    make build

# Collect eBPF object files for runtime loading.
RUN set -eux; \
    mkdir -p /workspace/out/sslsniff; \
    cp /workspace/sslsniff/*_x86_bpfel.o /workspace/out/sslsniff/

# Use distroless base with libc support for eBPF helpers.
FROM gcr.io/distroless/base-debian12
COPY --from=builder /workspace/bin/app /usr/local/bin/collector
COPY --from=builder /workspace/out/sslsniff/ssl_x86_bpfel.o /sslsniff/ssl_x86_bpfel.o
COPY --from=builder /workspace/out/sslsniff/rustls_x86_bpfel.o /sslsniff/rustls_x86_bpfel.o
CMD ["/usr/local/bin/collector"]
