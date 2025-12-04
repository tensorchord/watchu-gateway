# Watchu Gateway Developer Guide

## Project Layout

- `cmd/gateway`: Application entrypoint, configuration bootstrap, and wiring.
- `pkg/config`: Environment-based configuration loading and validation.
- `pkg/database`: PostgreSQL connection pool helpers and migration utilities.
- `pkg/server`: Lightweight HTTP server wrapper that handles graceful shutdown.
- `pkg/httpapi`: Gin router registration, request/response DTOs, and HTTP handlers.
- `pkg/ingest`: COPY-based ingestion services and payload validation.
- `pkg/analysis`: Incremental analysis scheduler orchestration and helpers.
- `pkg/gen/sqlc`: Go bindings generated from `db/sqlc` queries (via `sqlc`).
- `db/migrations`: Atlas SQL migrations applied on start-up or during local dev.
- `db/sqlc`: SQL schema definitions and query files that feed `sqlc generate`.
- `pkg/docs`: Generated Swagger assets (refresh with `make swagger`).
- `scripts`: Utility scripts (e.g. Swagger generation, setup helpers).

## API Documentation

1. Generate the Swagger spec and embedded docs:
   ```bash
   make swagger
   ```
2. Start the service (locally or via Docker) and visit `http://localhost:8080/swagger/index.html` (or simply `/` or `/swagger`, which redirect there) to browse the APIs.
3. Health endpoints: `GET /healthz` for liveness and `GET /readyz` for readiness.
4. Metrics endpoint: `GET /metrics` exposes Prometheus metrics via `promhttp`.
5. Incremental analysis: when enabled (`ANALYSIS_ENABLED=true`), a background scheduler copies recent HTTP traffic into `process_http_events`, materializes lightweight rows in `correlation_summary`, and raises simple heuristic alerts for recurring 5xx responses.

## Database Design Summary

The service stores raw telemetry and analysis results in PostgreSQL. Core tables:

- `http_request` / `http_response`: HTTP lineage captured from agents. UUIDv7 primary keys, JSONB headers, optional body payloads.
- `exec_events`: Process execution lineage with UUIDv7 identifiers.
- `process_http_events`, `correlation_summaries`, `heuristic_alerts`: Analysis outputs materialized by the incremental scheduler.
- `mcp_stdio_event` + `mcp_events_normalized`: Unified MCP capture (HTTP + STDIO) that feeds trace derivations.
- `llm_http_event` + `llm_tool_call_event`: Provider-agnostic cache of normalized LLM calls (keyed by `http_response_id` and the matched `http_request_id`) and any nested tool invocations lifted out of HTTP responses.

The SQL helper `populate_llm_http_events(host, since, until)` decodes Gemini and Claude-style JSON payloads out of `response_lineage`, attaches the originating `http_request_id`, writes the normalized rows above, and ensures any embedded usage counters (token counts, durations, etc.) are preserved for downstream trace generation.

### Agent & Trace Hierarchy

Version 0.3.0 introduces end-to-end storage for higher-level Agent observability:

- `agent_run`: Anchors each root process tree (`host + root_exec_id`) with provider hints and lifecycle timestamps.
- `trace`: Represents derived work units (`llm_call`, `tool_use`, `mcp_call`, `command_exec`, etc.) linked to an `agent_run` with optional parent/child relationships. Rows now include a `phase` (`default`, `request`, `response`) so request/response pairs for the same `external_id` can coexist instead of overwriting one another.
- `resource_usage`: Key/value style metrics (tokens, duration, tool counts) associated with individual traces.

The database ships with `upsert_agent_hierarchy(host, since, until)` which merges new exec + MCP evidence into the hierarchy. LLM calls and tool invocations are stitched in by correlating `llm_http_event` / `llm_tool_call_event` rows against the owning `agent_run`, emitting additional `trace(trace_type='llm_call')` and `trace(trace_type='tool_use')` records plus `resource_usage` metrics (input/output/total tokens) whenever providers report usage.

The incremental scheduler now runs the following order every tick:

1. `populate_process_http_events`
2. `populate_llm_http_events` (new)
3. `populate_correlation_summary`
4. `populate_heuristic_alerts`
5. `upsert_agent_hierarchy`

Schema definitions live under `db/migrations` (Atlas migrations) and `db/sqlc/schema`. Queries used by handlers live in `db/sqlc/queries`.

## Local Development Workflow

1. **Dependencies**
   - Go 1.25+
   - PostgreSQL 18 (or rely on Docker Compose)
   - `sqlc`, `atlas`, and `swag` CLIs for code generation.
   - `golangci-lint` for linting (`make lint`).

2. **Generate Code & Docs**
   ```bash
   sqlc generate
   make swagger
   ```

3. **Format & Lint**
   ```bash
   make fmt
   make lint
   ```

4. **Run Unit Tests**
   ```bash
   make test
   ```

5. **Launch Services**
   - Native: export `DATABASE_URL` then `make run`.
    - Docker Compose:
       ```bash
       make compose-up
       ```
       Stop with `make compose-down`.
    - When running under Docker, PostgreSQL 18+ stores data under `/var/lib/postgresql`; remove existing `pgdata` volumes if you previously mounted `/var/lib/postgresql/data`. The schema bootstraps from `db/migrations` via `/docker-entrypoint-initdb.d`, so drop the volume (`docker compose down -v`) whenever you change migrations.

6. **Analysis Scheduler**
   Configure via environment variables (`ANALYSIS_*`). Disable by leaving `ANALYSIS_ENABLED` unset or `false`.

## Local Testing Tips

- Use the example JSON payloads in `docs/examples` (create as needed) to POST batches to `/api/v1/ingest/http_request`, `/api/v1/ingest/http_response`, `/api/v1/ingest/exec_event`, or `/api/v1/ingest/mcp_stdio` for STDIO MCP traffic.
- Query analytics endpoints with parameters such as `GET /api/v1/analysis/correlation_summaries?host=node-1&since=2024-01-01T00:00:00Z&until=2024-01-02T00:00:00Z` (omit `until` to default to the current time).
- Check service health at `/healthz` and API docs at `/swagger/index.html`.

## Generated Assets

Generated artifacts (`pkg/docs`, `pkg/gen/sqlc`) should be regenerated whenever handlers or queries change. Run `sqlc generate` after updating files under `db/sqlc`, and rerun `make swagger` whenever you modify handler annotations.
