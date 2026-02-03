-- Skill Security SaaS Schema (Unified Migration)
-- This migration consolidates the SaaS feature including:
-- - Base tables: skills, skill_analyses, findings, notifications
-- - Correlation ID support for precise analysis isolation
-- - Unified security_events table
-- - All indexes, triggers, and functions

-- ============================================================================
-- Skills Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS skills (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    name TEXT NOT NULL,
    description TEXT,
    source_type TEXT NOT NULL CHECK (source_type IN ('upload', 'git', 'registry')),
    source_uri TEXT,
    s3_path TEXT NOT NULL,
    s3_bucket TEXT NOT NULL,
    checksum TEXT,
    size_bytes BIGINT,
    content_type TEXT,
    version TEXT DEFAULT '1.0.0',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    last_analysis_id UUID,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_skills_created_at ON skills(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_skills_source_type ON skills(source_type);
CREATE INDEX IF NOT EXISTS idx_skills_s3_path ON skills(s3_path);
CREATE INDEX IF NOT EXISTS idx_skills_deleted_at ON skills(deleted_at) WHERE deleted_at IS NOT NULL;

-- ============================================================================
-- Skill Analyses Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS skill_analyses (
    -- Primary keys
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    skill_id UUID REFERENCES skills(id) ON DELETE CASCADE,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Status
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),

    -- Error handling
    error_message TEXT,

    -- Runner integration
    runner_run_id TEXT,
    runner_output TEXT,
    runner_exit_code INTEGER,

    -- Source information
    source_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    resolved_ref TEXT,
    artifact_path TEXT,

    -- Agent info
    agent_type TEXT NOT NULL DEFAULT 'claude-code',
    runner_mode TEXT NOT NULL DEFAULT 'local',
    prompt_strategy TEXT NOT NULL DEFAULT 'from-skill',
    prompt_input TEXT,

    -- Execution tracking
    root_exec_id TEXT,
    agent_run_id UUID REFERENCES agent_run(id) ON DELETE SET NULL,

    -- SaaS fields
    engine_version TEXT,
    total_findings INTEGER DEFAULT 0,
    severity_summary JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::jsonb,

    -- Soft delete support
    deleted_at TIMESTAMPTZ,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_skill_analyses_skill_id ON skill_analyses(skill_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_skill_analyses_status ON skill_analyses(status);
CREATE INDEX IF NOT EXISTS idx_skill_analyses_deleted_at ON skill_analyses(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_skill_analyses_runner_run_id ON skill_analyses(runner_run_id) WHERE runner_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_skill_analyses_root_exec_id ON skill_analyses(root_exec_id) WHERE root_exec_id IS NOT NULL;

-- ============================================================================
-- Findings Table (Static Analysis - Legacy, will be migrated to security_events)
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    analysis_id UUID NOT NULL REFERENCES skill_analyses(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    location TEXT,
    code_snippet TEXT,
    recommendation TEXT,
    reference_links JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_findings_analysis_id ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);

-- ============================================================================
-- Notifications Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id TEXT,
    type TEXT NOT NULL CHECK (type IN ('analysis_complete', 'analysis_failed', 'finding_detected', 'system')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    read_at TIMESTAMPTZ,
    dismissed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    analysis_id UUID REFERENCES skill_analyses(id) ON DELETE CASCADE,
    skill_id UUID REFERENCES skills(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_analysis_id ON notifications(analysis_id) WHERE analysis_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_skill_id ON notifications(skill_id, created_at DESC) WHERE skill_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_read_at ON notifications(read_at) WHERE read_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_deleted_at ON notifications(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_dismissed_at ON notifications(dismissed_at) WHERE dismissed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_analysis_and_deleted ON notifications(analysis_id, deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_skill_and_deleted ON notifications(skill_id, deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_read_and_dismissed ON notifications(read_at, dismissed_at) WHERE read_at IS NULL AND dismissed_at IS NULL;

-- ============================================================================
-- Unified Security Events Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS security_events (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    -- Foreign key to skill_analyses
    analysis_id UUID NOT NULL REFERENCES skill_analyses(id) ON DELETE CASCADE,

    -- Data source type
    source_type TEXT NOT NULL CHECK (source_type IN ('static', 'dynamic', 'unified')),

    -- Severity classification
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'none')),

    -- Threat/finding category
    category TEXT,

    -- Event title and description
    title TEXT NOT NULL,
    description TEXT,

    -- Confidence score (0.0 - 1.0)
    confidence DECIMAL(3,2) DEFAULT 1.0,

    -- Static analysis specific fields
    code_snippet TEXT,
    file_path TEXT,
    reference_links JSONB DEFAULT '[]'::jsonb,

    -- Dynamic analysis and overall assessment specific fields
    telemetry_summary JSONB,
    threat_analysis_status TEXT CHECK (threat_analysis_status IN ('pending', 'running', 'ready', 'rate_limited', 'skipped', 'failed')),
    ai_generated_summary TEXT,
    recommendations JSONB DEFAULT '[]'::jsonb,
    evidence JSONB DEFAULT '[]'::jsonb,

    -- Metadata for extensibility
    metadata JSONB DEFAULT '{}'::jsonb,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Ensure one event per source per analysis
    CONSTRAINT unique_source_per_analysis UNIQUE (analysis_id, source_type)
);

CREATE INDEX IF NOT EXISTS idx_security_events_analysis_id ON security_events(analysis_id);
CREATE INDEX IF NOT EXISTS idx_security_events_source_type ON security_events(source_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_category ON security_events(category);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at DESC);

-- ============================================================================
-- Modifications to existing tables for correlation support
-- ============================================================================

-- Add correlation_id to exec_events for precise analysis-to-process association
ALTER TABLE exec_events
ADD COLUMN IF NOT EXISTS correlation_id TEXT;

CREATE INDEX IF NOT EXISTS idx_exec_events_correlation_id
ON exec_events(correlation_id)
WHERE correlation_id IS NOT NULL;

COMMENT ON COLUMN exec_events.correlation_id IS 'Unique identifier passed from skill_analysis.id via WATCHU_CORRELATION_ID environment variable, enabling precise association between analysis and process execution tree';

-- Add analysis_id to security_analysis_results for linking to skill_analyses
ALTER TABLE security_analysis_results
ADD COLUMN IF NOT EXISTS analysis_id UUID REFERENCES skill_analyses(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_security_analysis_results_analysis_id
ON security_analysis_results(analysis_id)
WHERE analysis_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_security_analysis_results_root_exec_and_analysis
ON security_analysis_results(root_exec_id, analysis_id)
WHERE analysis_id IS NOT NULL;

-- Add correlation_id to agent_threat_reports for precise analysis-to-threat association
ALTER TABLE agent_threat_reports
ADD COLUMN IF NOT EXISTS correlation_id TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_correlation_id
ON agent_threat_reports(correlation_id)
WHERE correlation_id IS NOT NULL;

COMMENT ON COLUMN agent_threat_reports.correlation_id IS 'Unique identifier matching skill_analysis.id, enabling precise association between agent-detected threats and specific skill analysis runs. This avoids ambiguity when multiple analyses share the same root_exec_id.';

-- ============================================================================
-- Triggers and Functions
-- ============================================================================

-- Function to update skills.updated_at
CREATE OR REPLACE FUNCTION update_skills_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_skills_updated_at ON skills;
CREATE TRIGGER trigger_update_skills_updated_at
    BEFORE UPDATE ON skills
    FOR EACH ROW
    EXECUTE FUNCTION update_skills_updated_at();

-- Function to update skill_analyses.updated_at
CREATE OR REPLACE FUNCTION update_skill_analyses_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_skill_analyses_updated_at ON skill_analyses;
CREATE TRIGGER trigger_update_skill_analyses_updated_at
    BEFORE UPDATE ON skill_analyses
    FOR EACH ROW
    EXECUTE FUNCTION update_skill_analyses_updated_at();

-- Function to update skills.last_analysis_id
CREATE OR REPLACE FUNCTION update_skill_last_analysis()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' THEN
        UPDATE skills SET last_analysis_id = NEW.id WHERE id = NEW.skill_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_skill_last_analysis ON skill_analyses;
CREATE TRIGGER trigger_update_skill_last_analysis
    AFTER UPDATE ON skill_analyses
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION update_skill_last_analysis();

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE skills IS 'Skill definitions for security analysis';
COMMENT ON TABLE skill_analyses IS 'Unified analysis table combining skill_security_runs and skill_analyses';
COMMENT ON TABLE findings IS 'Static analysis findings (legacy, being migrated to security_events)';
COMMENT ON TABLE notifications IS 'User notifications for analysis events';
COMMENT ON TABLE security_events IS 'Unified security events table consolidating static analysis (findings) and dynamic analysis (telemetry)';
COMMENT ON COLUMN security_events.source_type IS 'Source type: static=code analysis, dynamic=runtime behavior, unified=LLM-aggregated result from both sources';
COMMENT ON COLUMN security_events.code_snippet IS 'Code snippet from static analysis (only for source_type=static)';
COMMENT ON COLUMN security_events.telemetry_summary IS 'Telemetry data summary (for source_type=dynamic)';
COMMENT ON COLUMN security_events.threat_analysis_status IS 'Threat analysis status for dynamic events: pending/ready/rate_limited/skipped/failed';
COMMENT ON COLUMN security_events.ai_generated_summary IS 'AI-generated overall assessment (for source_type=overall)';
COMMENT ON CONSTRAINT unique_source_per_analysis ON security_events IS 'Ensure one event per source type per analysis';
