-- Create execution_traces table to store parsed runner output
CREATE TABLE IF NOT EXISTS execution_traces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID NOT NULL UNIQUE REFERENCES skill_analyses(id) ON DELETE CASCADE,

    -- Basic information
    session_id VARCHAR(255),
    status VARCHAR(50),
    duration_ms INTEGER,
    num_turns INTEGER,
    total_cost_usd NUMERIC(10, 6),

    -- Parsed results (JSONB format)
    tool_calls JSONB NOT NULL,
    file_access JSONB NOT NULL,
    external_access JSONB NOT NULL,
    timeline JSONB NOT NULL,
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    security_alerts JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Statistics (for efficient querying)
    total_tool_calls INTEGER DEFAULT 0,
    total_file_access INTEGER DEFAULT 0,
    total_external_access INTEGER DEFAULT 0,
    total_errors INTEGER DEFAULT 0,
    total_security_alerts INTEGER DEFAULT 0,

    -- Metadata
    parsed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    parser_version VARCHAR(50),

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_execution_traces_analysis_id ON execution_traces(analysis_id);
CREATE INDEX IF NOT EXISTS idx_execution_traces_status ON execution_traces(status);
CREATE INDEX IF NOT EXISTS idx_execution_traces_parsed_at ON execution_traces(parsed_at);
CREATE INDEX IF NOT EXISTS idx_execution_traces_tool_calls_gin ON execution_traces USING GIN (tool_calls);
CREATE INDEX IF NOT EXISTS idx_execution_traces_file_access_gin ON execution_traces USING GIN (file_access);
CREATE INDEX IF NOT EXISTS idx_execution_traces_external_access_gin ON execution_traces USING GIN (external_access);
