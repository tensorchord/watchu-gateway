FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY cmd ./cmd
COPY pkg ./pkg
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/skill-runner ./cmd/runner

FROM alpine:3.19
COPY --from=builder /bin/skill-runner /usr/local/bin/skill-runner
EXPOSE 8091
ENTRYPOINT ["/usr/local/bin/skill-runner"]
