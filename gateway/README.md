# Watchu Gateway

The gateway is the ingestion and analysis plane for TensorChord Watchu. It accepts raw
telemetry (HTTP requests/responses, exec events, MCP/stdio logs), incrementally builds
agent/trace relationships inside PostgreSQL, and exposes analytics APIs plus Prometheus
metrics for downstream systems.

## Key capabilities

- **High-throughput ingestion** – `/api/v1/ingest/*` endpoints accept batched HTTP,
  process, and MCP events, persisting them via `pkg/ingest` with minimal per-request
  overhead.
- **Incremental analysis scheduler** – `pkg/analysis.Scheduler` periodically refreshes
  process lifecycles, correlates HTTP activity, derives agent/trace hierarchies, and
  maintains heuristic alerts.
- **LLM prompt injection detection** – pending HTTP prompts are scored via an
  OpenAI-compatible model, and results are written to `llm_prompt_injection_results` plus
  `heuristic_alerts`.
- **Rich analytics API** – `/api/v1/analysis/*` provides host inventories, correlation
  summaries, heuristic alerts, process trees, security LLM summaries, and prompt injection
  details. Interactive docs live at `/swagger`.
- **Operational hooks** – `/metrics` exports Prometheus counters/histograms and the server
  honors graceful shutdown windows.

## Configuration

Environment variables control runtime behavior. Values shown below are defaults from
`pkg/config`.

### Core runtime

| Variable | Default | Description |
| --- | --- | --- |
| `GATEWAY_ADDRESS` | `:8080` | Listen address for the HTTP server. |
| `DATABASE_URL` | _required_ | PostgreSQL connection string for both ingestion and analysis. |
| `SHUTDOWN_TIMEOUT` | `15s` | Graceful shutdown window for in-flight HTTP requests. |

### Analysis scheduler

| Variable | Default | Description |
| --- | --- | --- |
| `ANALYSIS_ENABLED` | `true` | Master switch for the scheduler goroutine. |
| `ANALYSIS_TICK_INTERVAL` | `30s` | Period between scheduler iterations. |
| `ANALYSIS_HOST_LOOKBACK` | `1m` | Window used to pick “active” hosts. |
| `ANALYSIS_HORIZON` | `1m` | Extra overlap applied when refreshing historical windows. |
| `ANALYSIS_LAG` | `1s` | Delay applied to “until” timestamps to avoid racing new data. |
| `ANALYSIS_MAX_WINDOW` | `10m` | Max time window processed per tick to prevent long catch-up scans. |

### Prompt injection detection

| Variable | Default | Description |
| --- | --- | --- |
| `PROMPT_INJECTION_ENABLED` | `true` | Master switch for the detector. Disable if no compatible model is available. |
| `PROMPT_INJECTION_API_BASE` | `https://api.openai.com/v1` | Base URL of an OpenAI-compatible `/chat/completions` endpoint. |
| `PROMPT_INJECTION_API_KEY` | _empty_ | Bearer token sent with each detection call. Leave empty for unauthenticated backends. |
| `PROMPT_INJECTION_MODEL` | `gpt-4o` | Model name passed to the completion API. |
| `PROMPT_INJECTION_MODE` | `prompt_based` | `prompt_based` wraps prompts in a guardrail template; `model_based` sends the raw prompt text. |
| `PROMPT_INJECTION_TIMEOUT` | `15s` | Detection HTTP timeout. |
| `PROMPT_INJECTION_BATCH_SIZE` | `10` | Maximum pending requests processed per scheduler loop. |
| `PROMPT_INJECTION_MAX_RETRIES` | `3` | Retries before a request is skipped. Incremented via `prompt_injection_errors`. |
| `PROMPT_INJECTION_SAMPLE_RATE` | `1.0` | Hash-based sampling fraction (0–1). |
| `PROMPT_INJECTION_MAX_QPS` | `1.0` | Per-host rate limit applied before calling the model. |
| `PROMPT_INJECTION_MAX_PROMPT_CHARS` | `8192` | Maximum characters kept from the reconstructed prompt. |
| `PROMPT_INJECTION_STRIP_TOOL_CALLS` | `true` | If true, tool-call JSON is removed from prompts to reduce noise. |

## Database tables & views

Gateway persists everything in PostgreSQL (see `db/migrations/000003_agent_hierarchy.sql`). The
tables/views below are what the scheduler expects when deriving runs, traces, metrics, and prompt
injection outcomes.

### Core hierarchy tables

| Name | Role | Notable columns |
| --- | --- | --- |
| `agent_run` | One row per top-level agent session discovered from `process_lifecycle`. | `host`, `root_exec_id`, `provider`, `started_at`, `ended_at`. |
| `trace` | Child activities underneath an `agent_run` (`llm_call`, `tool_use`, `mcp_call`, `command_exec`). | `trace_type`, `parent_trace_id`, `external_id`, `phase`, `started_at/ended_at`. |
| `resource_usage` | Token/time counters keyed to a `trace`. Populated from provider telemetry or heuristics. | `metric` (`input_tokens`, `output_tokens`, `cached_input_tokens`, etc.), `value`, `unit`. |

### Normalized LLM + tool payloads

| Name | Type | Purpose |
| --- | --- | --- |
| `llm_http_event` | table | Provider-agnostic cache of raw HTTP request/response pairs, including prompt/response JSON, usage, and execution lineage. |
| `llm_tool_call_event` | table | One row per tool/function call lifted from LLM responses so the scheduler can mint `tool_use` traces. |
| `llm_prompt_injection_results` | table | Guardrail verdicts for pending requests with pointers back to `trace_id`, severity metadata, and scoring info. |
| `prompt_injection_errors` | table | Retry bookkeeping for failed detector calls; scheduler decrements remaining attempts based on this table. |

### MCP ingestion surface

| Name | Type | Purpose |
| --- | --- | --- |
| `mcp_stdio_event` | table | Raw JSON-RPC messages captured directly from STDIO transports (timestamp, pid, params/result/error blobs). |
| `mcp_events_normalized` | view | Unifies HTTP-derived MCP traffic (`process_http_events`) and STDIO rows into a single stream consumed by `upsert_agent_hierarchy`. Adds exec lineage + consistent `corr_id`. |

### Supporting process views

- `process_lifecycle`, `process_http_events`, `response_lineage`: populated by the collector pipeline and
  treated as staging tables. The gateway’s `populate_*` functions read these to decide which hosts or
  response IDs require new runs/traces.
- Helper functions such as `safe_json_from_bytea`, `safe_text_from_bytea`, and
  `strip_sse_data` live in the same migration and handle provider-specific quirks (Gemini SSE chunks,
  malformed JSON, etc.).

> **Tip:** If you extend the schema, re-run `atlas migrate hash` after editing `db/migrations` so the
> checksum matches what `atlas migrate apply` expects.

## API overview

### Ingestion (`/api/v1/ingest`)

- `POST /http_request` – batch of HTTP request events.
- `POST /http_response` – batch of HTTP response events.
- `POST /exec_event` – process execution telemetry.
- `POST /mcp_stdio` – MCP JSON-RPC events captured from STDIO.

All ingest endpoints expect JSON payloads defined in `pkg/httpapi` and return `202` on
success.

### Analysis & forensics (`/api/v1/analysis`)

Selected endpoints (full list documented under `/swagger`):

- `GET /hosts` – enumerate active hosts.
- `GET /correlation_summaries` – list HTTP response correlations for a host/time range.
- `GET /heuristic_alerts` – query stored alerts (including prompt injection events).
- `GET /security_llm_analysis` – aggregated semantic and prompt-injection verdicts per host.
- `GET /prompt_injections/{request_id}` – retrieve the HTTP payload tied to a detection.
- `GET /process_http_events`, `/process_events`, `/process_tree`, `/process_summary/{root_pid}` –
  inspect collected process telemetry.

### Prompt injection workflow details

For every scheduler slice, the gateway fetches pending HTTP requests from
`llm_http_event`, renders a guardrail prompt, and calls the configured model. Results are
stored in `llm_prompt_injection_results` and high-severity detections raise
`prompt_injection` rows inside `heuristic_alerts`.

- `GET /api/v1/analysis/security_llm_analysis?host=<host>` includes a `prompt_injections`
  array with severity, categories, and timestamps.
- `GET /api/v1/analysis/prompt_injections/{request_id}?host=<host>` returns the full HTTP
  request envelope for deeper investigation.
- High-severity detections propagate through the standard `heuristic_alerts` feed with
  `alert_type="prompt_injection"` for downstream paging/dashboarding.

### Operational notes

- The scheduler commits DB work before running the prompt detector to keep failures from
  blocking ingestion.
- Detection requests are JSON POSTs to `/chat/completions`, so any OpenAI-compatible
  provider (self-hosted, Azure OpenAI, etc.) is supported as long as it honors that shape.
- Use the `llm_prompt_injection_results` table (and Prometheus counters in
  `pkg/promptinjection/metrics.go`) for historical or monitoring workflows beyond the HTTP
  APIs.
