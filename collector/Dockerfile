# this is only for amd64
FROM ghcr.io/kemingy/ebpf-builder:0.1.0 AS builder

WORKDIR /workspace
COPY . .
RUN make build

FROM gcr.io/distroless/static-debian12
COPY --from=builder /workspace/bin/app /usr/local/bin/collector
CMD ["/usr/local/bin/collector"]
