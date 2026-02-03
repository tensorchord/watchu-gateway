-- Security Insight Analysis Queries
-- This file contains SQL queries for LLM-powered security analysis

-- name: GetEventsByRootExecID :many
WITH unioned AS (
    SELECT
        'http_request' as event_type,
        r.host,
        r.timestamp,
        r.pid,
        COALESCE(sqlc.narg('tid_int')::INTEGER, r.tid)::INTEGER AS tid,
        COALESCE(sqlc.narg('method_text')::TEXT, r.method)::TEXT AS method,
        COALESCE(sqlc.narg('url_text')::TEXT, r.url)::TEXT AS url,
        r.comm,
        NULL::INTEGER as status_code,
        NULL::TEXT as protocol,
        NULL::INTEGER as ppid,
        NULL::TEXT as args,
        NULL::TEXT as exec_id
    FROM http_request r
    WHERE EXISTS (
        SELECT 1 FROM process_lifecycle pl
        WHERE pl.root_exec_id = sqlc.arg('root_exec_id')
          AND pl.host = r.host
          AND pl.pid = r.pid
    )
    UNION ALL
    SELECT
        'http_response' as event_type,
        r.host,
        r.timestamp,
        r.pid,
        COALESCE(sqlc.narg('tid_int')::INTEGER, r.tid)::INTEGER AS tid,
        COALESCE(sqlc.narg('method_text')::TEXT, ''::TEXT)::TEXT AS method,
        COALESCE(sqlc.narg('url_text')::TEXT, ''::TEXT)::TEXT AS url,
        r.comm,
        r.status_code,
        r.protocol,
        NULL::INTEGER as ppid,
        NULL::TEXT as args,
        NULL::TEXT as exec_id
    FROM http_response r
    WHERE EXISTS (
        SELECT 1 FROM process_lifecycle pl
        WHERE pl.root_exec_id = sqlc.arg('root_exec_id')
          AND pl.host = r.host
          AND pl.pid = r.pid
    )
    UNION ALL
    SELECT
        'exec_event' as event_type,
        e.host,
        e.timestamp,
        e.pid,
        COALESCE(sqlc.narg('tid_int')::INTEGER, 0::INTEGER)::INTEGER AS tid,
        COALESCE(sqlc.narg('method_text')::TEXT, ''::TEXT)::TEXT AS method,
        COALESCE(sqlc.narg('url_text')::TEXT, ''::TEXT)::TEXT AS url,
        e.comm,
        NULL::INTEGER as status_code,
        NULL::TEXT as protocol,
        e.ppid,
        e.args,
        e.exec_id
    FROM exec_events e
    WHERE EXISTS (
        SELECT 1 FROM process_lifecycle pl
        WHERE pl.root_exec_id = sqlc.arg('root_exec_id')
          AND pl.host = e.host
          AND pl.exec_id = e.exec_id
    )
)
SELECT
    event_type,
    host,
    timestamp,
    pid,
    tid,
    method,
    url,
    comm,
    status_code,
    protocol,
    ppid,
    args,
    exec_id
FROM unioned
ORDER BY timestamp;

-- name: GetEventsByCorrelationID :many
-- Get events for a specific skill analysis using correlation_id (analysis_id)
-- This provides precise per-analysis event isolation, avoiding root_exec_id sharing issues
WITH analysis_processes AS (
    -- Get all processes that belong to this analysis via correlation_id
    SELECT DISTINCT e.host, e.exec_id, e.pid
    FROM exec_events e
    WHERE e.correlation_id = sqlc.arg('correlation_id')::text
),
unioned AS (
    SELECT
        'http_request' as event_type,
        r.host,
        r.timestamp,
        r.pid,
        COALESCE(sqlc.narg('tid_int')::INTEGER, r.tid)::INTEGER AS tid,
        COALESCE(sqlc.narg('method_text')::TEXT, r.method)::TEXT AS method,
        COALESCE(sqlc.narg('url_text')::TEXT, r.url)::TEXT AS url,
        r.comm,
        NULL::INTEGER as status_code,
        NULL::TEXT as protocol,
        NULL::INTEGER as ppid,
        NULL::TEXT as args,
        NULL::TEXT as exec_id
    FROM http_request r
    WHERE EXISTS (
        SELECT 1 FROM analysis_processes ap
        WHERE ap.host = r.host AND ap.pid = r.pid
    )
    UNION ALL
    SELECT
        'http_response' as event_type,
        r.host,
        r.timestamp,
        r.pid,
        COALESCE(sqlc.narg('tid_int')::INTEGER, r.tid)::INTEGER AS tid,
        COALESCE(sqlc.narg('method_text')::TEXT, ''::TEXT)::TEXT AS method,
        COALESCE(sqlc.narg('url_text')::TEXT, ''::TEXT)::TEXT AS url,
        r.comm,
        r.status_code,
        r.protocol,
        NULL::INTEGER as ppid,
        NULL::TEXT as args,
        NULL::TEXT as exec_id
    FROM http_response r
    WHERE EXISTS (
        SELECT 1 FROM analysis_processes ap
        WHERE ap.host = r.host AND ap.pid = r.pid
    )
    UNION ALL
    SELECT
        'exec_event' as event_type,
        e.host,
        e.timestamp,
        e.pid,
        COALESCE(sqlc.narg('tid_int')::INTEGER, 0::INTEGER)::INTEGER AS tid,
        COALESCE(sqlc.narg('method_text')::TEXT, ''::TEXT)::TEXT AS method,
        COALESCE(sqlc.narg('url_text')::TEXT, ''::TEXT)::TEXT AS url,
        e.comm,
        NULL::INTEGER as status_code,
        NULL::TEXT as protocol,
        e.ppid,
        e.args,
        e.exec_id
    FROM exec_events e
    WHERE e.correlation_id = sqlc.arg('correlation_id')::text
)
SELECT
    event_type,
    host,
    timestamp,
    pid,
    tid,
    method,
    url,
    comm,
    status_code,
    protocol,
    ppid,
    args,
    exec_id
FROM unioned
ORDER BY timestamp;

-- name: GetHeuristicAlertsByRootExecID :many
SELECT
    alert_id,
    alert_type,
    host,
    severity,
    score,
    start_ts,
    end_ts,
    details,
    reason
FROM heuristic_alerts
WHERE root_exec_id = sqlc.arg('root_exec_id')
ORDER BY start_ts;

-- name: InsertSecurityAnalysisResult :exec
INSERT INTO security_analysis_results (
    id,
    analyzed_at,
    host,
    root_exec_id,
    analysis_id,
    threat_level,
    threat_type,
    confidence,
    summary,
    details,
    recommendations,
    evidence,
    raw_json
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('analyzed_at'),
    sqlc.arg('host'),
    sqlc.arg('root_exec_id'),
    sqlc.arg('analysis_id'),
    sqlc.arg('threat_level'),
    sqlc.arg('threat_type'),
    sqlc.arg('confidence'),
    sqlc.arg('summary'),
    sqlc.arg('details'),
    sqlc.arg('recommendations'),
    sqlc.arg('evidence'),
    sqlc.arg('raw_json')
);

-- name: GetLatestSecurityAnalysisByRootExecID :one
SELECT
    id,
    analyzed_at,
    host,
    root_exec_id,
    analysis_id,
    threat_level,
    threat_type,
    confidence,
    summary,
    details,
    recommendations,
    evidence,
    raw_json
FROM security_analysis_results
WHERE root_exec_id = sqlc.arg('root_exec_id')
  AND id IS NOT NULL
ORDER BY analyzed_at DESC NULLS LAST, id DESC
LIMIT 1;

-- name: GetLatestSecurityAnalysisByAnalysisID :one
SELECT
    id,
    analyzed_at,
    host,
    root_exec_id,
    analysis_id,
    threat_level,
    threat_type,
    confidence,
    summary,
    details,
    recommendations,
    evidence,
    raw_json
FROM security_analysis_results
WHERE analysis_id = sqlc.arg('analysis_id')
  AND id IS NOT NULL
ORDER BY analyzed_at DESC NULLS LAST, id DESC
LIMIT 1;

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
WHERE host = sqlc.arg('host')
ORDER BY analyzed_at DESC
LIMIT sqlc.arg('limit');

-- name: GetSecurityAnalysisByID :one
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
    evidence,
    raw_json
FROM security_analysis_results
WHERE id = sqlc.arg('id');

-- name: ListPromptInjectionsByHost :many
SELECT
    res.request_id,
    res.host,
    res.severity_level,
    res.categories,
    res.score,
    res.model,
    res.detected_at,
    res.trace_id,
    res.agent_run_id,
    res.prompt_hash,
    res.metadata,
    res.reason,
    COALESCE(e.started_at, req.timestamp) AS observed_at
FROM llm_prompt_injection_results AS res
LEFT JOIN llm_http_event AS e
  ON e.host = res.host
 AND e.http_request_id = res.request_id
LEFT JOIN http_request AS req
  ON req.id = res.request_id
WHERE res.host = sqlc.arg('host')
ORDER BY COALESCE(e.started_at, req.timestamp) DESC NULLS LAST, res.request_id
LIMIT sqlc.arg('limit');

-- name: ListHeuristicAlertsByHostRange :many
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
WHERE host = sqlc.arg('host')
  AND start_ts >= sqlc.arg('since')
  AND start_ts <= sqlc.arg('until')
ORDER BY start_ts DESC
LIMIT sqlc.arg('limit');

-- name: GetPromptInjectionMetadataByHostAndRequestID :one
SELECT
    metadata
FROM llm_prompt_injection_results
WHERE host = sqlc.arg('host')
  AND request_id = sqlc.arg('request_id');

-- name: ListCompletedAnalysesWithoutThreatAnalysis :many
SELECT
    sa.id,
    sa.root_exec_id,
    sa.status
FROM skill_analyses sa
WHERE sa.status = 'completed'
  AND sa.root_exec_id IS NOT NULL
  AND sa.root_exec_id != ''
  AND NOT EXISTS (
      SELECT 1
      FROM security_analysis_results sar
      WHERE sar.root_exec_id = sa.root_exec_id
  )
ORDER BY sa.id DESC
LIMIT sqlc.arg('limit');
