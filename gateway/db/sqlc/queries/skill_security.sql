-- name: InsertSkillSecurityRun :one
INSERT INTO skill_security_runs (
    source_type,
    source_ref,
    resolved_ref,
    artifact_path,
    agent_type,
    runner_mode,
    prompt_strategy,
    prompt_input,
    status,
    error,
    runner_run_id,
    runner_output,
    runner_exit_code,
    root_exec_id,
    agent_run_id
) VALUES (
    sqlc.arg('source_type'),
    sqlc.arg('source_ref'),
    sqlc.arg('resolved_ref'),
    sqlc.arg('artifact_path'),
    sqlc.arg('agent_type'),
    sqlc.arg('runner_mode'),
    sqlc.arg('prompt_strategy'),
    sqlc.arg('prompt_input'),
    sqlc.arg('status'),
    sqlc.arg('error'),
    sqlc.arg('runner_run_id'),
    sqlc.arg('runner_output'),
    sqlc.arg('runner_exit_code'),
    sqlc.arg('root_exec_id'),
    sqlc.arg('agent_run_id')
)
RETURNING id, created_at, updated_at, source_type, source_ref, resolved_ref, artifact_path,
          agent_type, runner_mode, prompt_strategy, prompt_input, status, error, runner_run_id, runner_output, runner_exit_code, root_exec_id, agent_run_id;

-- name: UpdateSkillSecurityRunStatus :exec
UPDATE skill_security_runs
SET status = sqlc.arg('status'),
    error = sqlc.arg('error'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: UpdateSkillSecurityRunResult :exec
UPDATE skill_security_runs
SET status = sqlc.arg('status'),
    error = sqlc.arg('error'),
    runner_output = sqlc.arg('runner_output'),
    runner_exit_code = sqlc.arg('runner_exit_code'),
    root_exec_id = sqlc.arg('root_exec_id'),
    agent_run_id = sqlc.arg('agent_run_id'),
    prompt_input = sqlc.arg('prompt_input'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: UpdateSkillSecurityRunRunner :exec
UPDATE skill_security_runs
SET runner_run_id = sqlc.arg('runner_run_id'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: UpdateSkillSecurityRunRootExec :exec
UPDATE skill_security_runs
SET root_exec_id = sqlc.arg('root_exec_id'),
    agent_run_id = sqlc.arg('agent_run_id'),
    status = sqlc.arg('status'),
    updated_at = sqlc.arg('updated_at')
WHERE id = sqlc.arg('id');

-- name: GetSkillSecurityRunByID :one
SELECT
    id,
    created_at,
    updated_at,
    source_type,
    source_ref,
    resolved_ref,
    artifact_path,
    agent_type,
    runner_mode,
    prompt_strategy,
    prompt_input,
    status,
    error,
    runner_run_id,
    runner_output,
    runner_exit_code,
    root_exec_id,
    agent_run_id
FROM skill_security_runs
WHERE id = $1;

-- name: ListSkillSecurityRuns :many
SELECT
    id,
    created_at,
    updated_at,
    source_type,
    source_ref,
    resolved_ref,
    artifact_path,
    agent_type,
    runner_mode,
    prompt_strategy,
    prompt_input,
    status,
    error,
    runner_run_id,
    runner_output,
    runner_exit_code,
    root_exec_id,
    agent_run_id
FROM skill_security_runs
WHERE (sqlc.arg('status') = '' OR status = sqlc.arg('status'))
  AND (sqlc.arg('source_type') = '' OR source_type = sqlc.arg('source_type'))
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
FROM skill_security_runs
WHERE (sqlc.arg('source_type') = '' OR source_type = sqlc.arg('source_type'))
GROUP BY source_type, source_ref, artifact_path
ORDER BY MAX(created_at) DESC
LIMIT sqlc.arg('limit');

-- name: GetSkillRuns :many
SELECT
    id,
    created_at,
    updated_at,
    source_type,
    source_ref,
    resolved_ref,
    artifact_path,
    agent_type,
    runner_mode,
    prompt_strategy,
    prompt_input,
    status,
    error,
    runner_run_id,
    runner_output,
    runner_exit_code,
    root_exec_id,
    agent_run_id
FROM skill_security_runs
WHERE source_ref = sqlc.arg('source_ref')
  AND (sqlc.arg('artifact_path') = '' OR artifact_path = sqlc.arg('artifact_path'))
ORDER BY created_at DESC;

-- name: GetSkillSecurityRunByRootExecID :one
SELECT
    id,
    created_at,
    updated_at,
    source_type,
    source_ref,
    resolved_ref,
    artifact_path,
    agent_type,
    runner_mode,
    prompt_strategy,
    prompt_input,
    status,
    error,
    runner_run_id,
    runner_output,
    runner_exit_code,
    root_exec_id,
    agent_run_id
FROM skill_security_runs
WHERE root_exec_id = $1
ORDER BY created_at DESC
LIMIT 1;
