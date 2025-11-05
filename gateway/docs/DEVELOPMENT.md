# Watchu Gateway Developer Guide

## Project Layout

- `cmd/gateway`: Application entrypoint, config wiring, server bootstrap.
- `internal/config`: Environment-based configuration loading.
- `internal/database`: Database connection pool helpers.
- `internal/ingest`: COPY-based ingestion services and event DTOs.
- `internal/httpapi`: Gin router registration, request/response models, and handlers.
- `internal/analysis`: Incremental analysis scheduler orchestration.
- `db/sqlc`: SQL schema and query definitions used by `sqlc`.
- `pkg/docs`: Generated Swagger assets (run `make swagger` to refresh).
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
         PostgreSQL 18+ stores data under `/var/lib/postgresql`; remove existing `pgdata` volumes if you previously mounted `/var/lib/postgresql/data`. Schema bootstraps from `db/migrations` via `/docker-entrypoint-initdb.d`, so drop the volume (`docker compose down -v`) whenever you change migrations.

5. **Analysis Scheduler**
   Configure via environment variables (`ANALYSIS_*`). Disable by leaving `ANALYSIS_ENABLED` unset or `false`.

## Local Testing Tips

- Use the example JSON payloads in `docs/examples` (create as needed) to POST batches to `/api/v1/ingest/http_request`, `/api/v1/ingest/http_response`, or `/api/v1/ingest/exec_event`.
- Query analytics endpoints with parameters such as `GET /api/v1/analysis/correlation_summaries?host=node-1&since=2024-01-01T00:00:00Z`.
- Check service health at `/healthz` and API docs at `/swagger/index.html`.

## Generated Assets

Generated artifacts (`pkg/docs`, `internal/gen/sqlc`) should be regenerated whenever handlers or queries change. The Makefile and scripts directory expose the required tooling commands.
