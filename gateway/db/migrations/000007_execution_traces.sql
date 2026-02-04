-- Create execution_traces table to store parsed runner output
-- This table stores the structured execution trace data parsed from skill_analyses.runner_output

CREATE TABLE execution_traces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID NOT NULL UNIQUE REFERENCES skill_analyses(id) ON DELETE CASCADE,

    -- Basic information
    session_id VARCHAR(255),
    status VARCHAR(50),
    duration_ms INTEGER,
    num_turns INTEGER,
    total_cost_usd NUMERIC(10, 6),

    -- Parsed results (JSONB format)
    tool_calls JSONB NOT NULL,          -- []ToolCall
    file_access JSONB NOT NULL,         -- []FileAccess
    external_access JSONB NOT NULL,     -- []ExternalAccess
    timeline JSONB NOT NULL,            -- []TimelineEvent
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,     -- []ErrorRecord
    security_alerts JSONB NOT NULL DEFAULT '[]'::jsonb, -- []SecurityAlert

    -- Statistics (for efficient querying)
    total_tool_calls INTEGER DEFAULT 0,
    total_file_access INTEGER DEFAULT 0,
    total_external_access INTEGER DEFAULT 0,
    total_errors INTEGER DEFAULT 0,
    total_security_alerts INTEGER DEFAULT 0,

    -- Metadata
    parsed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    parser_version VARCHAR(50),         -- Record parser version

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_execution_traces_analysis_id ON execution_traces(analysis_id);
CREATE INDEX idx_execution_traces_status ON execution_traces(status);
CREATE INDEX idx_execution_traces_parsed_at ON execution_traces(parsed_at);

-- JSONB indexes (accelerate queries)
CREATE INDEX idx_execution_traces_tool_calls_gin ON execution_traces USING GIN (tool_calls);
CREATE INDEX idx_execution_traces_file_access_gin ON execution_traces USING GIN (file_access);
CREATE INDEX idx_execution_traces_external_access_gin ON execution_traces USING GIN (external_access);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_execution_traces_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at
CREATE TRIGGER execution_traces_updated_at
    BEFORE UPDATE ON execution_traces
    FOR EACH ROW
    EXECUTE FUNCTION update_execution_traces_updated_at();

-- Comment
COMMENT ON TABLE execution_traces IS 'Stores structured execution trace data parsed from skill_analyses.runner_output';
COMMENT ON COLUMN execution_traces.analysis_id IS 'Reference to the skill analysis';
COMMENT ON COLUMN execution_traces.tool_calls IS 'JSON array of tool calls';
COMMENT ON COLUMN execution_traces.file_access IS 'JSON array of file access records';
COMMENT ON COLUMN execution_traces.external_access IS 'JSON array of external access records';
COMMENT ON COLUMN execution_traces.timeline IS 'JSON array of timeline events';
COMMENT ON COLUMN execution_traces.parser_version IS 'Version of the parser used to generate this trace';
