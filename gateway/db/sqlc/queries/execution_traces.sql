-- name: GetRunnerOutputForParsing :many
SELECT runner_output, agent_type
FROM skill_analyses
WHERE id = $1;

-- name: InsertExecutionTrace :one
INSERT INTO execution_traces (
    analysis_id, session_id, status, duration_ms, num_turns, total_cost_usd,
    tool_calls, file_access, external_access, timeline, errors, security_alerts,
    total_tool_calls, total_file_access, total_external_access, total_errors, total_security_alerts,
    parser_version
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
)
RETURNING *;

-- name: GetExecutionTraceByAnalysisID :one
SELECT
    session_id, status, duration_ms, num_turns, total_cost_usd,
    tool_calls, file_access, external_access, timeline, errors, security_alerts
FROM execution_traces
WHERE analysis_id = $1;

-- name: GetTimelineByAnalysisID :one
SELECT timeline
FROM execution_traces
WHERE analysis_id = $1;

-- name: ListExecutionTraces :many
SELECT
    analysis_id, session_id, status, duration_ms, num_turns, total_cost_usd,
    total_tool_calls, total_file_access, total_errors, total_security_alerts, parsed_at
FROM execution_traces
ORDER BY parsed_at DESC
LIMIT $1 OFFSET $2;

-- name: CheckExecutionTraceExists :one
SELECT EXISTS(
    SELECT 1 FROM execution_traces WHERE analysis_id = $1
);
