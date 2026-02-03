-- name: CreateSaaSSkill :one
INSERT INTO skills (
    name, description, source_type, source_uri,
    s3_path, s3_bucket, checksum, size_bytes, content_type, version, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
RETURNING *;

-- name: GetSaaSSkillByID :one
SELECT * FROM skills WHERE id = $1;

-- name: ListSaaSSkills :many
SELECT * FROM skills
WHERE deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $1
OFFSET $2;

-- name: ListSaaSSkillsBySource :many
SELECT * FROM skills
WHERE source_type = $1 AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2
OFFSET $3;

-- name: UpdateSaaSSkill :one
UPDATE skills SET
    name = COALESCE($1, name),
    description = COALESCE($2, description),
    metadata = COALESCE($3, metadata),
    deleted_at = $4,
    updated_at = now()
WHERE id = $5
RETURNING *;

-- name: DeleteSaaSSkill :exec
DELETE FROM skills WHERE id = $1;

-- name: CreateSaaSSkillAnalysis :one
INSERT INTO skill_analyses (
    skill_id, status, engine_version, metadata
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetSaaSSkillAnalysisByID :one
SELECT 
    sa.*,
    s.name as skill_name,
    s.source_type as skill_source_type
FROM skill_analyses sa
LEFT JOIN skills s ON sa.skill_id = s.id
WHERE sa.id = $1 AND sa.deleted_at IS NULL;

-- name: GetSaaSSkillAnalysesBySkillID :many
SELECT 
    sa.*,
    s.name as skill_name,
    s.source_type as skill_source_type
FROM skill_analyses sa
LEFT JOIN skills s ON sa.skill_id = s.id
WHERE sa.skill_id = $1 AND sa.deleted_at IS NULL
ORDER BY sa.created_at DESC;

-- name: UpdateSaaSSkillAnalysisStatus :one
UPDATE skill_analyses SET
    status = $1,
    error_message = COALESCE($2, error_message),
    completed_at = CASE WHEN $1 IN ('completed', 'failed') THEN now() ELSE completed_at END
WHERE id = $3
RETURNING *;

-- name: UpdateSaaSSkillAnalysisResults :one
UPDATE skill_analyses SET
    status = $1,
    total_findings = $2,
    severity_summary = $3,
    error_message = COALESCE($4, error_message),
    completed_at = CASE WHEN $1 IN ('completed', 'failed') THEN now() ELSE completed_at END
WHERE id = $5
RETURNING *;

-- name: GetSaaSSecurityEventsByAnalysisID :many
SELECT * FROM security_events
WHERE analysis_id = $1
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
        WHEN 'none' THEN 6
    END,
    created_at DESC;

-- name: GetSaaSSecurityEventsByAnalysisIDWithFilter :many
SELECT * FROM security_events
WHERE analysis_id = $1
  AND ($2 = '' OR severity = $2)
  AND ($3 = '' OR category = $3)
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
        WHEN 'none' THEN 6
    END,
    created_at DESC
LIMIT $4
OFFSET $5;

-- name: DeleteSaaSSecurityEventsByAnalysisID :exec
DELETE FROM security_events WHERE analysis_id = $1;

-- name: CreateSaaSNotification :one
INSERT INTO notifications (
    user_id, type, title, message, metadata, analysis_id, skill_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING *;

-- name: GetSaaSNotificationsByUserID :many
SELECT * FROM notifications
WHERE user_id = $1 AND dismissed_at IS NULL AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2
OFFSET $3;

-- name: GetSaaSNotificationsByAnalysisID :many
SELECT * FROM notifications
WHERE analysis_id = $1 AND dismissed_at IS NULL AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: GetSaaSNotificationsBySkillID :many
SELECT * FROM notifications
WHERE skill_id = $1 AND dismissed_at IS NULL AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2
OFFSET $3;

-- name: GetSaaSUnreadNotificationsByUserID :many
SELECT * FROM notifications
WHERE user_id = $1 AND read_at IS NULL AND dismissed_at IS NULL AND deleted_at IS NULL
ORDER BY created_at DESC;

-- name: MarkSaaSNotificationAsRead :one
UPDATE notifications SET
    read_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: DismissSaaSNotification :one
UPDATE notifications SET
    dismissed_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: MarkAllSaaSNotificationsAsRead :exec
UPDATE notifications SET
    read_at = now()
WHERE user_id = $1 AND read_at IS NULL AND deleted_at IS NULL;

-- name: CountSaaSUnreadNotifications :one
SELECT COUNT(*) as unread_count
FROM notifications
WHERE user_id = $1 AND read_at IS NULL AND dismissed_at IS NULL AND deleted_at IS NULL;

-- name: DeleteSaaSSkillAnalysis :exec
DELETE FROM skill_analyses WHERE id = $1;

-- name: ResetSaaSSkillAnalysisForRerun :one
UPDATE skill_analyses SET
    status = 'pending',
    started_at = now(),
    completed_at = NULL,
    root_exec_id = NULL,
    agent_run_id = NULL,
    runner_run_id = NULL,
    runner_output = NULL,
    runner_exit_code = NULL,
    error_message = NULL,
    total_findings = 0,
    severity_summary = NULL,
    prompt_input = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: GetSaaSSkillAnalysisByRunnerRunID :one
SELECT * FROM skill_analyses WHERE runner_run_id = $1 AND deleted_at IS NULL;

-- name: UpdateSaaSSkillAnalysisFindings :one
UPDATE skill_analyses SET
    total_findings = $2,
    severity_summary = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: CascadeSoftDeleteAnalysesBySkillID :exec
UPDATE skill_analyses
SET deleted_at = $2
WHERE skill_id = $1 AND deleted_at IS NULL;

-- name: CascadeSoftDeleteNotificationsByAnalysisID :exec
UPDATE notifications
SET deleted_at = $2
WHERE analysis_id = $1 AND deleted_at IS NULL;

-- name: CascadeSoftDeleteNotificationsBySkillID :exec
UPDATE notifications
SET deleted_at = $2
WHERE skill_id = $1 AND deleted_at IS NULL;

-- name: ListSaaSSkillAnalyses :many
SELECT 
    sa.*,
    s.name as skill_name,
    s.source_type as skill_source_type
FROM skill_analyses sa
LEFT JOIN skills s ON sa.skill_id = s.id
WHERE ($1 = '' OR sa.status = $1)
  AND ($2 = '' OR sa.source_type = $2)
  AND sa.deleted_at IS NULL
ORDER BY sa.created_at DESC
LIMIT $3
OFFSET $4;

-- name: GetSaaSSkillRuns :many
SELECT
    sa.*,
    s.name as skill_name,
    s.source_type as skill_source_type
FROM skill_analyses sa
LEFT JOIN skills s ON sa.skill_id = s.id
WHERE sa.source_ref = $1
  AND ($2 = '' OR sa.artifact_path = $2)
  AND sa.deleted_at IS NULL
ORDER BY sa.created_at DESC;

-- Security Events queries

-- name: CreateSecurityEvent :one
INSERT INTO security_events (
    analysis_id, source_type, severity, category, title, description,
    confidence, code_snippet, file_path, reference_links,
    telemetry_summary, threat_analysis_status, ai_generated_summary, recommendations, evidence, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)
ON CONFLICT (analysis_id, source_type)
DO UPDATE SET
    severity = EXCLUDED.severity,
    category = EXCLUDED.category,
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    confidence = EXCLUDED.confidence,
    code_snippet = EXCLUDED.code_snippet,
    file_path = EXCLUDED.file_path,
    reference_links = EXCLUDED.reference_links,
    telemetry_summary = EXCLUDED.telemetry_summary,
    threat_analysis_status = EXCLUDED.threat_analysis_status,
    ai_generated_summary = EXCLUDED.ai_generated_summary,
    recommendations = EXCLUDED.recommendations,
    evidence = EXCLUDED.evidence,
    metadata = EXCLUDED.metadata
RETURNING *;

-- name: GetSecurityEventsByAnalysisID :many
SELECT * FROM security_events
WHERE analysis_id = $1
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
        WHEN 'none' THEN 6
    END,
    created_at DESC;

-- name: GetSecurityEventByAnalysisIDAndSourceType :one
SELECT * FROM security_events
WHERE analysis_id = $1 AND source_type = $2;

-- name: DeleteSecurityEventsByAnalysisID :exec
DELETE FROM security_events WHERE analysis_id = $1;

-- name: UpsertSecurityEvent :one
INSERT INTO security_events (
    analysis_id, source_type, severity, category, title, description,
    confidence, code_snippet, file_path, reference_links,
    telemetry_summary, threat_analysis_status, ai_generated_summary, recommendations, evidence, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)
ON CONFLICT (analysis_id, source_type)
DO UPDATE SET
    severity = EXCLUDED.severity,
    category = EXCLUDED.category,
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    confidence = EXCLUDED.confidence,
    code_snippet = EXCLUDED.code_snippet,
    file_path = EXCLUDED.file_path,
    reference_links = EXCLUDED.reference_links,
    telemetry_summary = EXCLUDED.telemetry_summary,
    threat_analysis_status = EXCLUDED.threat_analysis_status,
    ai_generated_summary = EXCLUDED.ai_generated_summary,
    recommendations = EXCLUDED.recommendations,
    evidence = EXCLUDED.evidence,
    metadata = EXCLUDED.metadata
RETURNING *;
