# WatchU

Hey, Agent! :honeybee: The bees are watching you! :honeybee:

## Highlights

- eBPF‑powered telemetry: TLS, HTTP, process, MCP StdIO, and Postgres client events with host/container context.
- Agent monitoring for claude-code, gemini-cli, and codex (runs, traces, tool use visibility).
- Zero‑config OpenSSL tracing: auto‑discover libssl in containers and attach uprobes (dynamic or static).
- Incremental analytics: process lifecycle, correlation, and ready‑to‑query derived tables.
- Data source intelligence: S3/Postgres TopN, distributions, and drill‑down access events.
- LLM‑powered safety signals: prompt‑injection checks, heuristic alerts, and evidence‑backed security insights.
- Insightful UI: process explorer, traces/agent runs, alerts, and data‑source dashboards.

## Usage

### Local (Docker Required)

```bash
cd deploy/docker
# You can customize the following environment variables as needed
ROMPT_INJECTION_API_BASE=http://host.docker.internal:4000 PROMPT_INJECTION_API_KEY=dump PROMPT_INJECTION_MODEL=github_copilot/gpt-4o PROMPT_INJECTION_MODE=prompt_based THREAT_INSIGHT_BASE_URL=http://host.docker.internal:4000 THREAT_INSIGHT_API_KEY=dump THREAT_INSIGHT_MODEL=github_copilot/gpt-4o docker compose -f docker-compose.yaml up --build
# Only initialize watchu service or need to migrate the database schema
atlas migrate apply --url "postgres://watchu:watchu@localhost:5432/watchu?sslmode=disable" --dir "file://../../gateway/db/migrations" -c "file://../../gateway/atlas.hcl"   
```

### Kubernetes

See [deploy/k8s/README.md](deploy/k8s/README.md) for instructions on deploying WatchU to Kubernetes.

## Development

### Collector

```bash
cd collector && make build

# run the tetragon service with Unix socket
docker run -d --name tetragon --rm \
    --pid=host --cgroupns=host --privileged \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
    -v /var/run/tetragon:/var/run/tetragon \
    quay.io/cilium/tetragon:v1.6.0 \
    --server-address unix:///var/run/tetragon/tetragon.sock

# run with MCP StdIO & SSL & Tetragon
sudo ./collector/bin/app -tetragon-path unix:///var/run/tetragon/tetragon.sock
# or run without Tetragon
sudo ./collector/bin/app
```

### Gateway & Frontend Usage

```bash
cd gateway && make compose-up
```

The gateway will be available at `http://localhost:8080`, the frontend will be available at `http://localhost:5173`.
