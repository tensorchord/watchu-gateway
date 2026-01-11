CREATE TABLE IF NOT EXISTS correlation_summary (
    host VARCHAR NOT NULL,
    response_id UUID NOT NULL,
    response_ts TIMESTAMPTZ,
    status_code INTEGER,
    method VARCHAR,
    url VARCHAR,
    root_exec_id VARCHAR,
    root_pid BIGINT,
    best_event_id UUID,
    best_event_exec_id VARCHAR,
    event_root_exec_id VARCHAR,
    event_root_pid BIGINT,
    best_event_comm VARCHAR,
    best_event_args VARCHAR,
    best_total_score NUMERIC,
    best_correlation_type VARCHAR,
    best_gap_ms DOUBLE PRECISION,
    best_lineage_score DOUBLE PRECISION,
    best_temporal_score DOUBLE PRECISION,
    best_argument_score DOUBLE PRECISION,
    best_argument_match_flag INTEGER,
    system_actions JSONB,
    evidence JSONB,
    PRIMARY KEY (host, response_id)
);

CREATE TABLE IF NOT EXISTS heuristic_alerts (
    alert_id TEXT PRIMARY KEY,
    alert_type TEXT NOT NULL,
    host VARCHAR NOT NULL,
    severity TEXT,
    score DOUBLE PRECISION,
    start_ts TIMESTAMPTZ NOT NULL,
    end_ts TIMESTAMPTZ,
    root_exec_id VARCHAR,
    root_pid BIGINT,
    details JSONB,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS process_http_events (
    host VARCHAR NOT NULL,
    http_id UUID NOT NULL,
    http_type VARCHAR NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER,
    tid INTEGER,
    method VARCHAR,
    url VARCHAR,
    status_code INTEGER,
    protocol VARCHAR,
    headers JSONB,
    body BYTEA,
    truncated BOOLEAN,
    exec_id VARCHAR,
    root_exec_id VARCHAR,
    root_pid BIGINT,
    depth INTEGER,
    is_mcp_http BOOLEAN
);

CREATE TABLE IF NOT EXISTS process_pg_events (
    host TEXT NOT NULL,
    pg_event_id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER,
    tid INTEGER,
    uid INTEGER,
    gid INTEGER,
    comm TEXT,
    msg_type TEXT,
    data BYTEA,
    container_id TEXT,
    exec_id TEXT,
    root_exec_id TEXT,
    root_pid BIGINT,
    depth INTEGER,
    sql_text TEXT,
    sql_hash TEXT,
    PRIMARY KEY (host, pg_event_id)
);

CREATE TABLE IF NOT EXISTS process_s3_events (
    host TEXT NOT NULL,
    response_id UUID NOT NULL,
    request_id UUID,
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER,
    tid INTEGER,
    comm TEXT,
    method TEXT,
    url TEXT,
    status_code INTEGER,
    bucket TEXT,
    bucket_region TEXT,
    object_key TEXT,
    request_bytes BIGINT,
    response_bytes BIGINT,
    container_id TEXT,
    exec_id TEXT,
    root_exec_id TEXT,
    root_pid BIGINT,
    depth INTEGER,
    operation TEXT,
    PRIMARY KEY (host, response_id)
);

CREATE TABLE IF NOT EXISTS process_lifecycle (
    host VARCHAR NOT NULL,
    exec_id VARCHAR NOT NULL,
    p_exec_id VARCHAR,
    pid BIGINT,
    ppid BIGINT,
    root_exec_id VARCHAR,
    root_pid BIGINT,
    depth INTEGER,
    start_ts TIMESTAMPTZ,
    end_ts TIMESTAMPTZ,
    cwd VARCHAR,
    comm VARCHAR,
    args VARCHAR,
    PRIMARY KEY (host, exec_id)
);


CREATE TABLE IF NOT EXISTS agent_run (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    host TEXT NOT NULL,
    root_exec_id TEXT,
    root_pid BIGINT,
    provider TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    UNIQUE (host, root_exec_id)
);

CREATE TABLE IF NOT EXISTS trace (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    agent_run_id UUID NOT NULL REFERENCES agent_run(id) ON DELETE CASCADE,
    parent_trace_id UUID REFERENCES trace(id) ON DELETE SET NULL,
    trace_type TEXT NOT NULL,
    source_table TEXT,
    source_id UUID,
    external_id TEXT,
    model TEXT,
    model_version TEXT,
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    phase TEXT NOT NULL DEFAULT 'default',
    UNIQUE (agent_run_id, trace_type, external_id, phase)
);

CREATE TABLE IF NOT EXISTS resource_usage (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    trace_id UUID NOT NULL REFERENCES trace(id) ON DELETE CASCADE,
    metric TEXT NOT NULL,
    value NUMERIC,
    unit TEXT,
    UNIQUE (trace_id, metric)
);

CREATE TABLE IF NOT EXISTS llm_http_event (
    host TEXT NOT NULL,
    http_response_id UUID NOT NULL,
    http_request_id UUID,
    response_key TEXT,
    provider TEXT,
    model TEXT,
    model_version TEXT,
    status TEXT,
    corr_id TEXT,
    prompt JSONB,
    response JSONB,
    usage JSONB,
    raw_request TEXT,
    raw_response TEXT,
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    exec_id TEXT,
    root_exec_id TEXT,
    root_pid BIGINT,
    PRIMARY KEY (host, http_response_id)
);

CREATE TABLE IF NOT EXISTS llm_tool_call_event (
    host TEXT NOT NULL,
    response_key TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    name TEXT,
    arguments JSONB,
    provider TEXT,
    PRIMARY KEY (host, response_key, tool_call_id)
);



CREATE TABLE IF NOT EXISTS security_analysis_results (
    id UUID PRIMARY KEY,
    analyzed_at TIMESTAMPTZ,
    host VARCHAR,
    root_exec_id VARCHAR,
    threat_level INTEGER,
    threat_type VARCHAR,
    confidence DOUBLE PRECISION,
    summary VARCHAR,
    details VARCHAR,
    recommendations JSONB,
    evidence JSONB,
    raw_json JSONB
);

CREATE TABLE IF NOT EXISTS skill_security_runs (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
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
    runner_run_id TEXT,
    runner_output TEXT,
    runner_exit_code INTEGER,
    root_exec_id TEXT,
    agent_run_id UUID REFERENCES agent_run(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS llm_prompt_injection_results (
    request_id UUID NOT NULL,
    host TEXT NOT NULL,
    severity_level TEXT NOT NULL,
    categories TEXT,
    trace_id UUID REFERENCES trace(id) ON DELETE SET NULL,
    agent_run_id UUID REFERENCES agent_run(id) ON DELETE SET NULL,
    prompt_hash TEXT,
    score DOUBLE PRECISION,
    model TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB,
    reason TEXT,
    PRIMARY KEY (host, request_id)
);

CREATE INDEX IF NOT EXISTS llm_prompt_injection_results_hash_idx
    ON llm_prompt_injection_results(prompt_hash)
    WHERE prompt_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS prompt_injection_errors (
    host TEXT NOT NULL,
    request_id UUID NOT NULL,
    last_error TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, request_id)
);

CREATE TABLE IF NOT EXISTS agent_threat_reports (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    host TEXT NOT NULL,
    root_exec_id TEXT,
    agent_type TEXT NOT NULL,
    agent_version TEXT,
    session_id TEXT,
    threat_type TEXT NOT NULL,
    threat_level INTEGER NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    title TEXT NOT NULL,
    description TEXT,
    evidence JSONB,
    detection_method TEXT,
    file_path TEXT,
    code_snippet TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    reviewed_at TIMESTAMPTZ,
    reviewed_by TEXT,
    metadata JSONB
);
