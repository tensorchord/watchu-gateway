# this is only for amd64
FROM quay.io/cilium/clang:b97f5b3d5c38da62fb009f21a53cd42aefd54a2f@sha256:e1c8ed0acd2e24ed05377f2861d8174af28e09bef3bbc79649c8eba165207df0 AS builder

RUN apt-get update && apt-get install -y linux-libc-dev gzip curl wget make
RUN wget -qO- https://go.dev/dl/go1.25.5.linux-amd64.tar.gz | tar -xz -C /usr/local
ENV PATH="${PATH}:/usr/local/go/bin:/usr/lib/llvm-18/bin"

WORKDIR /workspace
COPY . .
RUN make build

FROM ubuntu:24.04
COPY --from=builder /workspace/bin/app /usr/local/bin/collector
CMD ["/usr/local/bin/collector"]
