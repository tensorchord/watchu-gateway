CREATE TABLE IF NOT EXISTS skill_security_runs (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    resolved_ref TEXT,
    artifact_path TEXT,
    agent_type TEXT NOT NULL,
    runner_mode TEXT NOT NULL,
    prompt_strategy TEXT NOT NULL,
    prompt_input TEXT,
    status TEXT NOT NULL,
    error TEXT,
    root_exec_id TEXT,
    agent_run_id UUID REFERENCES agent_run(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_skill_security_runs_status
    ON skill_security_runs(status);

CREATE INDEX IF NOT EXISTS idx_skill_security_runs_created_at
    ON skill_security_runs(created_at DESC);
