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
    details JSONB
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

CREATE TABLE IF NOT EXISTS llm_prompt_injection_results (
    request_id UUID,
    host VARCHAR,
    severity_level VARCHAR,
    categories VARCHAR
);