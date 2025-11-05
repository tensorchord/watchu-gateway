-- name: ListCorrelationsByHostSince :many
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
WHERE host = $1
  AND response_ts > $2
ORDER BY response_ts DESC
LIMIT $3;

-- name: ListHeuristicAlertsByHostSince :many
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
    details
FROM heuristic_alerts
WHERE host = $1
  AND start_ts > $2
ORDER BY start_ts DESC
LIMIT $3;

-- name: ListProcessHTTPEventsByHostSince :many
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
WHERE host = $1
  AND timestamp > $2
ORDER BY timestamp DESC
LIMIT $3;

-- name: ListSecurityAnalysisByHost :many
SELECT
    id,
    analyzed_at,
    host,
    root_exec_id,
    threat_level,
    threat_type,
    confidence,
    summary,
    details,
    recommendations,
    evidence
FROM security_analysis_results
WHERE host = $1
ORDER BY analyzed_at DESC
LIMIT $2;

-- name: ListPromptInjectionsByHost :many
SELECT
    res.request_id,
    res.host,
    res.severity_level,
    res.categories,
    req.timestamp AS observed_at
FROM llm_prompt_injection_results AS res
LEFT JOIN http_request AS req
  ON req.id = res.request_id
WHERE res.host = $1
ORDER BY req.timestamp DESC NULLS LAST, res.request_id
LIMIT $2;

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

-- name: ListProcessEventsByHostSince :many
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
WHERE host = $1
  AND start_ts > $2
ORDER BY start_ts DESC
LIMIT $3;

-- name: ListProcessTreeRootsByHost :many
WITH roots AS (
  SELECT root_pid, MAX(start_ts) AS last_seen
  FROM process_lifecycle
  WHERE host = $1
  GROUP BY root_pid
)
SELECT root_pid
FROM roots
ORDER BY last_seen DESC NULLS LAST
LIMIT $2;

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
WHERE host = $1
  AND (
    (root_pid IS NOT NULL AND root_pid = ANY($2::bigint[]))
    OR (root_pid IS NULL AND $3::boolean)
  )
ORDER BY root_pid NULLS LAST, depth ASC, start_ts ASC
LIMIT $4;

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
    details
FROM heuristic_alerts
WHERE host = $1
  AND root_pid = $2
  AND ($3 = '' OR root_exec_id = $3)
ORDER BY severity DESC, score DESC
LIMIT $4;