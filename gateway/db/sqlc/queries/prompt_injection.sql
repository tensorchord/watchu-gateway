-- name: ListPromptInjectionCandidates :many
SELECT
    e.host,
    e.http_request_id AS request_id,
    e.http_response_id AS response_id,
    e.response_key,
    e.provider,
    e.model,
    e.prompt,
    e.raw_request,
    e.raw_response,
    e.started_at AS observed_at,
    e.exec_id,
    e.root_exec_id,
    e.root_pid,
    t.id AS trace_id,
    t.agent_run_id,
    err.retry_count,
    err.updated_at AS last_retry_at,
    err.last_error,
    ar.root_exec_id AS agent_root_exec_id,
    ar.root_pid AS agent_root_pid
FROM llm_http_event AS e
LEFT JOIN trace AS t
  ON t.source_id = e.http_request_id
 AND t.trace_type = 'llm_call'
 AND t.phase = 'request'
LEFT JOIN agent_run AS ar
  ON ar.id = t.agent_run_id
LEFT JOIN prompt_injection_errors AS err
  ON err.host = e.host AND err.request_id = e.http_request_id
WHERE e.host = sqlc.arg('host')
  AND e.started_at > sqlc.arg('since')
  AND e.started_at <= sqlc.arg('until')
  AND e.http_request_id IS NOT NULL
  AND (err.retry_count IS NULL OR err.retry_count < sqlc.arg('max_retries'))
  AND NOT EXISTS (
      SELECT 1
      FROM llm_prompt_injection_results AS res
      WHERE res.host = e.host
        AND res.request_id = e.http_request_id
  )
ORDER BY e.started_at DESC NULLS LAST
LIMIT sqlc.arg('limit');

-- name: UpsertPromptInjectionResult :exec
INSERT INTO llm_prompt_injection_results (
    host,
    request_id,
    severity_level,
    categories,
    trace_id,
    agent_run_id,
    prompt_hash,
    score,
    model,
    detected_at,
    metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
ON CONFLICT (host, request_id) DO UPDATE
SET severity_level = EXCLUDED.severity_level,
    categories = EXCLUDED.categories,
    trace_id = EXCLUDED.trace_id,
    agent_run_id = EXCLUDED.agent_run_id,
    prompt_hash = EXCLUDED.prompt_hash,
    score = EXCLUDED.score,
    model = EXCLUDED.model,
    detected_at = EXCLUDED.detected_at,
    metadata = EXCLUDED.metadata;

-- name: DeletePromptInjectionError :exec
DELETE FROM prompt_injection_errors
WHERE host = $1 AND request_id = $2;

-- name: UpsertPromptInjectionError :one
WITH upserted AS (
    INSERT INTO prompt_injection_errors (host, request_id, last_error, retry_count, updated_at)
    VALUES ($1, $2, $3, 1, $4)
    ON CONFLICT (host, request_id) DO UPDATE
    SET last_error = EXCLUDED.last_error,
        retry_count = prompt_injection_errors.retry_count + 1,
        updated_at = EXCLUDED.updated_at
    RETURNING retry_count, updated_at
)
SELECT retry_count, updated_at FROM upserted;

-- name: UpsertPromptInjectionAlert :exec
INSERT INTO heuristic_alerts (
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
) VALUES (
    $1, 'prompt_injection', $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (alert_id) DO UPDATE
SET severity = EXCLUDED.severity,
    score = EXCLUDED.score,
    start_ts = EXCLUDED.start_ts,
    end_ts = EXCLUDED.end_ts,
    root_exec_id = EXCLUDED.root_exec_id,
    root_pid = EXCLUDED.root_pid,
    details = EXCLUDED.details;
