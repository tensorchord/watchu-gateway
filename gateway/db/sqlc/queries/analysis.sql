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

-- name: UpsertAgentRunProvider :exec
INSERT INTO agent_run (host, root_exec_id, root_pid, provider, started_at, ended_at)
VALUES (
    sqlc.arg('host'),
    sqlc.arg('root_exec_id'),
    sqlc.arg('root_pid'),
    sqlc.arg('provider'),
    sqlc.arg('started_at'),
    sqlc.arg('ended_at')
)
ON CONFLICT (host, root_exec_id) DO UPDATE
SET provider = EXCLUDED.provider,
    root_pid = COALESCE(agent_run.root_pid, EXCLUDED.root_pid),
    started_at = LEAST(agent_run.started_at, EXCLUDED.started_at),
    ended_at = CASE
        WHEN agent_run.ended_at IS NULL THEN EXCLUDED.ended_at
        WHEN EXCLUDED.ended_at IS NULL THEN agent_run.ended_at
        ELSE GREATEST(agent_run.ended_at, EXCLUDED.ended_at)
    END;

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

-- name: GetAgentThreatReportsByRootExecID :many
SELECT
    id,
    created_at,
    host,
    root_exec_id,
    agent_type,
    agent_version,
    session_id,
    threat_type,
    threat_level,
    confidence,
    title,
    description,
    evidence,
    detection_method,
    file_path,
    code_snippet,
    status
FROM agent_threat_reports
WHERE root_exec_id = $1
  AND status = 'active'
ORDER BY threat_level DESC, created_at DESC;

-- name: GetAgentThreatReportsByCorrelationID :many
SELECT
    id,
    created_at,
    host,
    root_exec_id,
    correlation_id,
    agent_type,
    agent_version,
    session_id,
    threat_type,
    threat_level,
    confidence,
    title,
    description,
    evidence,
    detection_method,
    file_path,
    code_snippet,
    status
FROM agent_threat_reports
WHERE correlation_id = $1
  AND status = 'active'
ORDER BY threat_level DESC, created_at DESC;

-- name: UpsertAgentThreatReport :one
SELECT upsert_agent_threat_report(
    $1::text,   -- host
    $2::text,   -- root_exec_id
    $3::text,   -- agent_type
    $4::text,   -- agent_version
    $5::text,   -- session_id
    $6::text,   -- threat_type
    $7::int,    -- threat_level
    $8::real,   -- confidence
    $9::text,   -- title
    $10::text,  -- description
    $11::jsonb, -- evidence
    $12::text,  -- detection_method
    $13::text,  -- file_path
    $14::text,  -- code_snippet
    $15::jsonb  -- metadata
)::uuid AS report_id;

-- name: InsertAgentThreatReport :one
INSERT INTO agent_threat_reports (
    id,
    created_at,
    updated_at,
    host,
    root_exec_id,
    agent_type,
    agent_version,
    session_id,
    threat_type,
    threat_level,
    confidence,
    title,
    description,
    evidence,
    detection_method,
    file_path,
    code_snippet,
    status,
    metadata
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('created_at'),
    sqlc.arg('updated_at'),
    sqlc.arg('host'),
    sqlc.arg('root_exec_id'),
    sqlc.arg('agent_type'),
    sqlc.arg('agent_version'),
    sqlc.arg('session_id'),
    sqlc.arg('threat_type'),
    sqlc.arg('threat_level'),
    sqlc.arg('confidence'),
    sqlc.arg('title'),
    sqlc.arg('description'),
    sqlc.arg('evidence'),
    sqlc.arg('detection_method'),
    sqlc.arg('file_path'),
    sqlc.arg('code_snippet'),
    sqlc.arg('status'),
    sqlc.arg('metadata')
)
RETURNING id;

-- name: ListHostsFromExecEvents :many
-- Fallback query to get hosts from exec_events when process_lifecycle is empty
SELECT DISTINCT host
FROM exec_events
WHERE host IS NOT NULL AND host <> ''
  AND timestamp >= sqlc.arg('since')
  AND timestamp <= sqlc.arg('until')
ORDER BY host ASC
LIMIT sqlc.arg('limit');

-- name: RefreshProcessLifecycleForHost :one
-- Trigger incremental refresh of process_lifecycle for a specific host and time window
-- Uses advisory lock to prevent concurrent refreshes for the same host
-- Returns true if refresh was performed, false if skipped due to lock
SELECT CASE
    WHEN pg_try_advisory_xact_lock(hashtext(sqlc.arg('host')::varchar || sqlc.arg('since')::text)) THEN (
        SELECT refresh_process_lifecycle_incremental(
            sqlc.arg('host')::varchar,
            sqlc.arg('since')::timestamptz,
            sqlc.arg('until')::timestamptz
        ) IS NOT NULL
    )
    ELSE false
END AS refreshed;

-- name: ListExecEventsByHostRange :many
-- Direct query to exec_events for finding claude processes when process_lifecycle is stale
SELECT
    host,
    exec_id,
    p_exec_id,
    pid,
    ppid,
    timestamp AS start_ts,
    comm,
    args,
    cwd
FROM exec_events
WHERE host = sqlc.arg('host')
  AND timestamp >= sqlc.arg('since')
  AND timestamp <= sqlc.arg('until')
ORDER BY timestamp DESC
LIMIT sqlc.arg('limit');
