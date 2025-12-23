# WatchU

Hey, Agent! :honeybee: The bees are watching you! :honeybee:

## Highlights

- Full‑stack telemetry: TLS, HTTP, process, MCP StdIO, and Postgres client events with host/container context.
- Agent monitoring for claude-code, gemini-cli, and codex (runs, traces, tool use visibility).
- Zero‑config OpenSSL tracing: auto‑discover libssl in containers and attach uprobes (dynamic or static).
- Incremental analytics: process lifecycle, correlation, and ready‑to‑query derived tables.
- Data source intelligence: S3/Postgres TopN, distributions, and drill‑down access events.
- LLM‑powered safety signals: prompt‑injection checks, heuristic alerts, and evidence‑backed security insights.
- Insightful UI: process explorer, traces/agent runs, alerts, and data‑source dashboards.

## Collector Usage

- SSL read/write
- MCP StdIO
- Process

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

## Gateway & Frontend Usage

```bash
cd gateway && make compose-up
```

The gateway will be available at `http://localhost:8080`, the frontend will be available at `http://localhost:5173`.
