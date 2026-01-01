-- name: ListCorrelationsByHostRange :many
SELECT
    host,
    response_id,
    response_ts,
    status_code,
    method,
    url,
    root_exec_id,
    root_pid,
    best_event_id,
    best_event_exec_id,
    event_root_exec_id,
    event_root_pid,
    best_event_comm,
    best_event_args,
    best_total_score,
    best_correlation_type,
    best_gap_ms,
    best_lineage_score,
    best_temporal_score,
    best_argument_score,
    best_argument_match_flag,
    system_actions,
    evidence
FROM correlation_summary
WHERE host = sqlc.arg('host')
  AND response_ts >= sqlc.arg('since')
  AND response_ts <= sqlc.arg('until')
ORDER BY response_ts DESC
LIMIT sqlc.arg('limit');

-- name: ListProcessHTTPEventsByHostRange :many
SELECT
    host,
    http_id,
    http_type,
    timestamp,
    pid,
    tid,
    method,
    url,
    status_code,
    protocol,
    headers,
    body,
    truncated,
    exec_id,
    root_exec_id,
    root_pid,
    depth,
    is_mcp_http
FROM process_http_events
WHERE host = sqlc.arg('host')
  AND timestamp >= sqlc.arg('since')
  AND timestamp <= sqlc.arg('until')
ORDER BY timestamp DESC
LIMIT sqlc.arg('limit');

-- name: GetHTTPRequestByHostAndID :one
SELECT
    id,
    timestamp,
    pid,
    tid,
    uid,
    gid,
    comm,
    method,
    content_length,
    url,
    protocol,
    headers,
    body,
    truncated,
    host
FROM http_request
WHERE host = $1
  AND id = $2;

-- name: ListProcessEventsByHostRange :many
SELECT
    host,
    exec_id,
    p_exec_id,
    pid,
    ppid,
    root_exec_id,
    root_pid,
    depth,
    start_ts,
    end_ts,
    comm,
    args,
    cwd
FROM process_lifecycle
WHERE host = sqlc.arg('host')
  AND start_ts >= sqlc.arg('since')
  AND start_ts <= sqlc.arg('until')
ORDER BY start_ts DESC
LIMIT sqlc.arg('limit');

-- name: ListProcessTreeRootsByHost :many
WITH roots AS (
  SELECT root_pid, MAX(start_ts) AS last_seen
  FROM process_lifecycle
  WHERE host = sqlc.arg('host')
    AND (
      sqlc.arg('until')::timestamptz IS NULL OR start_ts <= sqlc.arg('until')::timestamptz
    )
    AND (
      sqlc.arg('since')::timestamptz IS NULL OR COALESCE(end_ts, 'infinity'::timestamptz) >= sqlc.arg('since')::timestamptz
    )
  GROUP BY root_pid
)
SELECT root_pid
FROM roots
ORDER BY last_seen DESC NULLS LAST
LIMIT sqlc.arg('limit');

-- name: ListProcessTreeNodesByRoots :many
SELECT
  host,
  exec_id,
  p_exec_id,
  pid,
  ppid,
  root_exec_id,
  root_pid,
  depth,
  start_ts,
  end_ts,
  comm,
  args,
  cwd
FROM process_lifecycle
WHERE host = sqlc.arg('host')::text
  AND (
    (sqlc.arg('root_exec_id')::text <> '' AND root_exec_id = sqlc.arg('root_exec_id')::text)
    OR (
      sqlc.arg('root_exec_id')::text = '' AND (
        (root_pid IS NOT NULL AND root_pid = ANY(sqlc.arg('root_pids')::bigint[]))
        OR (root_pid IS NULL AND sqlc.arg('include_null')::boolean)
      )
    )
  )
    AND (
      sqlc.arg('until')::timestamptz IS NULL OR start_ts <= sqlc.arg('until')::timestamptz
    )
    AND (
      sqlc.arg('since')::timestamptz IS NULL OR COALESCE(end_ts, 'infinity'::timestamptz) >= sqlc.arg('since')::timestamptz
    )
ORDER BY root_pid NULLS LAST, depth ASC, start_ts ASC
LIMIT sqlc.arg('limit');

-- name: GetProcessMetaByHostRoot :one
SELECT
  MAX(CASE WHEN depth = 0 THEN exec_id END)::varchar AS exec_id,
  MAX(CASE WHEN depth = 0 THEN comm END)::varchar AS comm,
  MAX(CASE WHEN depth = 0 THEN args END)::varchar AS args,
  MIN(start_ts)::timestamptz AS first_seen,
  MAX(end_ts)::timestamptz AS last_seen,
  COUNT(*)::bigint AS event_count
FROM process_lifecycle
WHERE host = $1
  AND root_pid = $2
  AND ($3 = '' OR root_exec_id = $3);

-- name: ListHeuristicAlertsByRoot :many
SELECT
    alert_id,
    alert_type,
    host,
    severity,
    score,
    start_ts,
    end_ts,
    root_exec_id,
    root_pid,
    details,
    reason
FROM heuristic_alerts
WHERE host = $1
  AND root_pid = $2
  AND ($3 = '' OR root_exec_id = $3)
ORDER BY severity DESC, score DESC
LIMIT $4;

-- name: ListHosts :many
SELECT DISTINCT host
FROM process_lifecycle
WHERE host IS NOT NULL AND host <> ''
ORDER BY host ASC
LIMIT $1;

-- name: ListAgentRunsByHostRange :many
SELECT
    id,
    host,
    root_exec_id,
    root_pid,
    provider,
    started_at,
    ended_at
FROM agent_run
WHERE host = sqlc.arg('host')
  AND started_at <= sqlc.arg('until')
  AND COALESCE(ended_at, sqlc.arg('until')) >= sqlc.arg('since')
ORDER BY started_at DESC NULLS LAST
LIMIT sqlc.arg('limit');

-- name: GetAgentRunByID :one
SELECT
    id,
    host,
    root_exec_id,
    root_pid,
    provider,
    started_at,
    ended_at
FROM agent_run
WHERE id = $1;

-- name: GetAgentRunByRootExecID :one
SELECT
    id,
    host,
    root_exec_id,
    root_pid,
    provider,
    started_at,
    ended_at
FROM agent_run
WHERE root_exec_id = $1
ORDER BY started_at DESC NULLS LAST
LIMIT 1;

-- name: ListTracesByAgentRun :many
SELECT
    id,
    agent_run_id,
    parent_trace_id,
    trace_type,
    source_table,
    source_id,
    external_id,
    model,
    model_version,
    started_at,
    ended_at,
    phase
FROM trace
WHERE agent_run_id = $1
ORDER BY COALESCE(started_at, ended_at) ASC NULLS LAST, id;

-- name: ListResourceUsageByTraceIDs :many
SELECT
    trace_id,
    metric,
    value,
    unit
FROM resource_usage
WHERE trace_id = ANY(sqlc.arg('trace_ids')::uuid[]);

-- name: ListLLMEventsByResponseKeys :many
SELECT
    host,
    response_key,
    provider,
    model,
    model_version,
    prompt,
    response,
    usage,
    raw_request,
    raw_response,
    status,
    exec_id,
    root_exec_id
FROM llm_http_event
WHERE host = $1
  AND response_key = ANY($2::text[]);

-- name: ListToolCallsByIDs :many
SELECT
    host,
    response_key,
    tool_call_id,
    name,
    arguments
FROM llm_tool_call_event
WHERE host = $1
  AND tool_call_id = ANY($2::text[]);

-- name: ListMcpEventsByCorrIDs :many
SELECT
  m.host,
  m.corr_id,
  m.message_type,
  m.method,
  m.params,
  m.result,
  m.error,
  m.timestamp,
  m.server,
  m.tool
FROM mcp_events_normalized m
WHERE m.host = $1
  AND m.corr_id = ANY($2::text[])
ORDER BY m.corr_id, m.timestamp;
