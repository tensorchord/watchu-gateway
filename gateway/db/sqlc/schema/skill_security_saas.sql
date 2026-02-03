-- Skill Security SaaS Schema
-- Schema for MVP: skills, analyses, findings, notifications
-- Merged schema: skill_analyses combines skill_security_runs + skill_analyses

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
    deleted_at TIMESTAMPTZ,  -- Soft delete support
    last_analysis_id UUID,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Merged table: skill_analyses (combines skill_security_runs + skill_analyses)
CREATE TABLE IF NOT EXISTS skill_analyses (
    -- Primary keys
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    skill_id UUID REFERENCES skills(id) ON DELETE CASCADE,  -- Nullable for watchu compatibility

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Status
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),

    -- Error handling
    error_message TEXT,

    -- Runner integration (from skill_security_runs)
    runner_run_id TEXT,
    runner_output TEXT,
    runner_exit_code INTEGER,

    -- Source information (from skill_security_runs)
    source_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    resolved_ref TEXT,
    artifact_path TEXT,

    -- Agent info (from skill_security_runs)
    agent_type TEXT NOT NULL DEFAULT 'claude-code',
    runner_mode TEXT NOT NULL DEFAULT 'local',
    prompt_strategy TEXT NOT NULL DEFAULT 'from-skill',
    prompt_input TEXT,

    -- Execution tracking (from skill_security_runs)
    root_exec_id TEXT,
    agent_run_id UUID REFERENCES agent_run(id) ON DELETE SET NULL,

    -- SaaS fields (from skill_analyses)
    engine_version TEXT,
    total_findings INTEGER DEFAULT 0,
    severity_summary JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::jsonb,

    -- Soft delete support
    deleted_at TIMESTAMPTZ,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb
);

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

-- Unified security_events table (consolidates findings and security_analyses)
CREATE TABLE IF NOT EXISTS security_events (
    -- Primary key
    id UUID PRIMARY KEY DEFAULT uuidv7(),

    -- Foreign key to skill_analyses
    analysis_id UUID NOT NULL REFERENCES skill_analyses(id) ON DELETE CASCADE,

    -- Data source type
    source_type TEXT NOT NULL CHECK (source_type IN ('static', 'dynamic')),

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

    -- Ensure one event per source per analysis (for latest result)
    CONSTRAINT unique_source_per_analysis UNIQUE (analysis_id, source_type)
);
