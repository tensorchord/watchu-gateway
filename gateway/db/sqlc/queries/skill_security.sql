-- name: InsertSkillAnalysis :one
INSERT INTO skill_analyses (
    skill_id,
    source_type,
    source_ref,
    resolved_ref,
    artifact_path,
    agent_type,
    runner_mode,
    prompt_strategy,
    prompt_input,
    status,
    error_message,
    runner_run_id,
    runner_output,
    runner_exit_code,
    root_exec_id,
    agent_run_id,
    started_at,
    created_at,
    updated_at
) VALUES (
    sqlc.arg('skill_id'),
    sqlc.arg('source_type'),
    sqlc.arg('source_ref'),
    sqlc.arg('resolved_ref'),
    sqlc.arg('artifact_path'),
    sqlc.arg('agent_type'),
    sqlc.arg('runner_mode'),
    sqlc.arg('prompt_strategy'),
    sqlc.arg('prompt_input'),
    sqlc.arg('status'),
    sqlc.arg('error_message'),
    sqlc.arg('runner_run_id'),
    sqlc.arg('runner_output'),
    sqlc.arg('runner_exit_code'),
    sqlc.arg('root_exec_id'),
    sqlc.arg('agent_run_id'),
    sqlc.arg('started_at'),
    sqlc.arg('created_at'),
    sqlc.arg('updated_at')
)
RETURNING *;

-- name: UpdateSkillAnalysisStatus :exec
UPDATE skill_analyses
SET status = sqlc.arg('status'),
    error_message = sqlc.arg('error_message'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: UpdateSkillAnalysisResult :exec
UPDATE skill_analyses
SET status = sqlc.arg('status'),
    error_message = sqlc.arg('error_message'),
    runner_output = sqlc.arg('runner_output'),
    runner_exit_code = sqlc.arg('runner_exit_code'),
    root_exec_id = sqlc.arg('root_exec_id'),
    agent_run_id = sqlc.arg('agent_run_id'),
    prompt_input = sqlc.arg('prompt_input'),
    completed_at = sqlc.arg('completed_at'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: UpdateSkillAnalysisRunner :exec
UPDATE skill_analyses
SET runner_run_id = sqlc.arg('runner_run_id'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: UpdateSkillAnalysisRootExec :exec
UPDATE skill_analyses
SET root_exec_id = sqlc.arg('root_exec_id'),
    agent_run_id = sqlc.arg('agent_run_id'),
    status = sqlc.arg('status'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: GetSkillAnalysisByID :one
SELECT * FROM skill_analyses
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListSkillAnalyses :many
SELECT * FROM skill_analyses
WHERE (sqlc.arg('status') = '' OR status = sqlc.arg('status'))
  AND (sqlc.arg('source_type') = '' OR source_type = sqlc.arg('source_type'))
  AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListSkills :many
SELECT DISTINCT
    source_type,
    source_ref,
    artifact_path,
    MAX(created_at) as last_run_at,
    COUNT(*) as run_count,
    (ARRAY_AGG(runner_mode ORDER BY created_at DESC))[1] as last_runner_mode
FROM skill_analyses
WHERE (sqlc.arg('source_type') = '' OR source_type = sqlc.arg('source_type'))
  AND deleted_at IS NULL
GROUP BY source_type, source_ref, artifact_path
ORDER BY MAX(created_at) DESC
LIMIT sqlc.arg('limit');

-- name: GetSkillRuns :many
SELECT * FROM skill_analyses
WHERE source_ref = sqlc.arg('source_ref')
  AND (sqlc.arg('artifact_path') = '' OR artifact_path = sqlc.arg('artifact_path'))
  AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: GetSkillAnalysisByRootExecID :one
SELECT * FROM skill_analyses
WHERE root_exec_id = $1
  AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: UpdateSkillAnalysisCompleted :exec
UPDATE skill_analyses
SET status = sqlc.arg('status'),
    completed_at = sqlc.arg('completed_at'),
    error_message = sqlc.arg('error_message'),
    total_findings = sqlc.arg('total_findings'),
    severity_summary = sqlc.arg('severity_summary'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');
