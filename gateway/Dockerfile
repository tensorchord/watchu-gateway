# syntax=docker/dockerfile:1

FROM golang:1.25 AS builder
WORKDIR /workspace

COPY go.mod go.sum ./
ENV GOPROXY=https://goproxy.cn,direct
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /workspace/bin/watchu-gateway ./cmd/gateway

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /

COPY --from=builder /workspace/bin/watchu-gateway /watchu-gateway

ENV GIN_MODE=release
EXPOSE 8080

ENTRYPOINT ["/watchu-gateway"]
