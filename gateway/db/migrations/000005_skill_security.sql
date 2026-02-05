-- Skill security runs table
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
    runner_run_id TEXT,
    runner_output TEXT,
    runner_exit_code INTEGER,
    root_exec_id TEXT,
    agent_run_id UUID REFERENCES agent_run(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_skill_security_runs_status
    ON skill_security_runs(status);

CREATE INDEX IF NOT EXISTS idx_skill_security_runs_created_at
    ON skill_security_runs(created_at DESC);

-- Fix strip_sse_data to properly handle Anthropic SSE format with tool_use support
-- Anthropic API returns Server-Sent Events with:
-- - message_start: contains message metadata (id, model, content array)
-- - content_block_start: defines a new content block (text, tool_use, thinking, etc.)
-- - content_block_delta: provides incremental updates to the current block
-- - content_block_stop: marks the end of the current block
-- - message_delta: contains message-level metadata (usage, stop_reason)

CREATE OR REPLACE FUNCTION strip_sse_data(p_text TEXT)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_line TEXT;
    v_last_data TEXT;
    v_response_json TEXT;
    v_anthropic_message JSONB;
    v_anthropic_usage JSONB;
    v_temp_json JSONB;
    v_accumulated_text TEXT := '';

    -- Track tool_use blocks
    v_tool_use_id TEXT;
    v_tool_use_name TEXT;
    v_tool_use_input TEXT := '';

    -- Track all content blocks in order
    v_has_content BOOLEAN := FALSE;
BEGIN
    IF p_text IS NULL THEN
        RETURN NULL;
    END IF;

    FOR v_line IN SELECT * FROM regexp_split_to_table(p_text, E'\n') LOOP
        IF v_line ~ '^\s*data:' THEN
            v_line := btrim(substring(v_line FROM '^\s*data:\s*(.*)$'));
            IF v_line IS NOT NULL AND v_line <> '' THEN
                v_last_data := v_line;

                -- Priority 1: Gemini responseId
                IF POSITION('"responseId"' IN v_line) > 0 THEN
                    v_response_json := v_line;
                END IF;

                -- Priority 2: Anthropic message_start (has id, model, content structure)
                IF POSITION('"type":"message_start"' IN v_line) > 0
                   OR POSITION('"type": "message_start"' IN v_line) > 0 THEN
                    -- Extract the nested "message" object
                    BEGIN
                        v_temp_json := v_line::jsonb;
                        IF v_temp_json ? 'message' THEN
                            v_anthropic_message := v_temp_json->'message';
                        END IF;
                    EXCEPTION WHEN OTHERS THEN
                        NULL;
                    END;
                END IF;

                -- Priority 3: Anthropic content_block_start (initiate a new content block)
                IF POSITION('"type":"content_block_start"' IN v_line) > 0
                   OR POSITION('"type": "content_block_start"' IN v_line) > 0 THEN
                    BEGIN
                        v_temp_json := v_line::jsonb;
                        IF v_temp_json ? 'content_block' THEN
                            DECLARE
                                v_content_block JSONB := v_temp_json->'content_block';
                                v_block_type TEXT := v_content_block->>'type';
                            BEGIN
                                -- For tool_use blocks, capture the initial metadata
                                IF v_block_type = 'tool_use' THEN
                                    v_tool_use_id := COALESCE(v_content_block->>'id', v_tool_use_id);
                                    v_tool_use_name := COALESCE(v_content_block->>'name', v_tool_use_name);
                                    v_tool_use_input := '';  -- Reset input for accumulation
                                    v_has_content := TRUE;
                                -- For text blocks, just mark that we have content
                                ELSIF v_block_type = 'text' THEN
                                    v_has_content := TRUE;
                                END IF;
                            END;
                        END IF;
                    EXCEPTION WHEN OTHERS THEN
                        NULL;
                    END;
                END IF;

                -- Priority 4: Anthropic content_block_delta (incremental updates to blocks)
                IF POSITION('"type":"content_block_delta"' IN v_line) > 0
                   OR POSITION('"type": "content_block_delta"' IN v_line) > 0 THEN
                    BEGIN
                        v_temp_json := v_line::jsonb;
                        IF v_temp_json ? 'delta' THEN
                            DECLARE
                                v_delta JSONB := v_temp_json->'delta';
                                v_delta_type TEXT := COALESCE(v_delta->>'type', '');
                            BEGIN
                                -- Handle text_delta for text blocks
                                IF v_delta_type = 'text_delta' AND v_delta ? 'text' THEN
                                    v_accumulated_text := v_accumulated_text || (v_delta->>'text');
                                    v_has_content := TRUE;
                                -- Handle input_json_delta for tool_use blocks
                                ELSIF v_delta_type = 'input_json_delta' AND v_delta ? 'partial_json' THEN
                                    v_tool_use_input := v_tool_use_input || (v_delta->>'partial_json');
                                    v_has_content := TRUE;
                                END IF;
                            END;
                        END IF;
                    EXCEPTION WHEN OTHERS THEN
                        NULL;
                    END;
                END IF;

                -- Priority 5: Anthropic message_delta (has final usage)
                IF POSITION('"type":"message_delta"' IN v_line) > 0
                   OR POSITION('"type": "message_delta"' IN v_line) > 0 THEN
                    -- Extract usage from message_delta
                    BEGIN
                        v_temp_json := v_line::jsonb;
                        IF v_temp_json ? 'usage' THEN
                            v_anthropic_usage := v_temp_json->'usage';
                        END IF;
                    EXCEPTION WHEN OTHERS THEN
                        NULL;
                    END;
                END IF;
            END IF;
        END IF;
    END LOOP;

    -- Return Gemini response if found
    IF v_response_json IS NOT NULL THEN
        RETURN v_response_json;
    END IF;

    -- Return Anthropic message with reconstructed content blocks
    IF v_anthropic_message IS NOT NULL THEN
        DECLARE
            v_content_array JSONB := '[]'::jsonb;
        BEGIN
            -- Reconstruct content array from accumulated data
            IF v_has_content THEN
                -- Add text block if we have accumulated text
                IF v_accumulated_text <> '' THEN
                    v_content_array := v_content_array || jsonb_build_object(
                        'type', 'text',
                        'text', v_accumulated_text
                    );
                END IF;

                -- Add tool_use block if we captured tool_use data
                IF v_tool_use_id IS NOT NULL THEN
                    v_content_array := v_content_array || jsonb_build_object(
                        'type', 'tool_use',
                        'id', v_tool_use_id,
                        'name', COALESCE(v_tool_use_name, 'unknown'),
                        'input', CASE
                            WHEN v_tool_use_input <> '' THEN
                                -- Try to parse as JSON, fall back to string
                                (v_tool_use_input::jsonb)
                            ELSE
                                '{}'::jsonb
                        END
                    );
                END IF;
            END IF;

            -- Set reconstructed content array
            IF jsonb_array_length(v_content_array) > 0 THEN
                v_anthropic_message := jsonb_set(
                    v_anthropic_message,
                    '{content}',
                    v_content_array
                );
            END IF;

            -- Merge usage into message if available
            IF v_anthropic_usage IS NOT NULL THEN
                v_anthropic_message := jsonb_set(
                    v_anthropic_message,
                    '{usage}',
                    v_anthropic_usage
                );
            END IF;

            RETURN v_anthropic_message::text;
        END;
    END IF;

    -- Fallback to last data line
    IF v_last_data IS NOT NULL THEN
        RETURN v_last_data;
    END IF;

    RETURN p_text;
END;
$$;

-- Fix populate_llm_http_events to handle duplicate response_id in response_lineage
-- (due to multiple process_lifecycle entries for the same PID)
-- Adds DISTINCT ON (response_id) to the src CTE to deduplicate entries

CREATE OR REPLACE FUNCTION populate_llm_http_events(
    p_host  TEXT,
    p_since TIMESTAMPTZ,
    p_until TIMESTAMPTZ
) RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    v_rows INTEGER := 0;
BEGIN
    WITH src AS (
        SELECT DISTINCT ON (rl.response_id)
            rl.host,
            rl.response_id,
            rl.response_ts,
            rl.exec_id,
            rl.root_exec_id,
            rl.root_pid,
            req_match.id AS http_request_id,
            safe_json_from_bytea(rl.request_body)  AS req_json,
            -- Parse SSE format to extract proper JSON structure
            NULLIF(strip_sse_data(safe_text_from_bytea(rl.response_body)), '')::jsonb AS resp_json,
            safe_text_from_bytea(rl.request_body)  AS raw_request,
            safe_text_from_bytea(rl.response_body) AS raw_response
        FROM response_lineage rl
        LEFT JOIN LATERAL (
            SELECT req.id
            FROM http_request req
            WHERE req.host = rl.host
              AND req.pid = rl.pid
              AND req.timestamp <= rl.response_ts
            ORDER BY req.timestamp DESC
            LIMIT 1
        ) AS req_match(id) ON TRUE
        WHERE rl.host = p_host
          AND rl.response_ts > p_since
          AND rl.response_ts <= p_until
        ORDER BY rl.response_id, rl.response_ts
    ),
    normalized AS (
        SELECT
            s.*,
            CASE
                WHEN s.resp_json ? 'responseId' THEN 'gemini'
                WHEN COALESCE(s.resp_json->>'type', '') LIKE 'message%' THEN 'claude-code'
                ELSE NULL
            END AS provider
        FROM src s
        WHERE s.resp_json IS NOT NULL
    ),
    prepared AS (
        SELECT
            n.host,
            n.response_id,
            n.response_ts,
            n.exec_id,
            n.root_exec_id,
            n.root_pid,
            n.http_request_id,
            n.provider,
            n.req_json,
            n.resp_json,
            n.raw_request,
            n.raw_response,
            CASE
                WHEN n.provider = 'gemini' THEN n.resp_json->>'responseId'
                WHEN n.provider = 'claude-code' THEN COALESCE(n.resp_json->>'id', n.resp_json->>'response_id')
            END AS response_key,
            CASE
                WHEN n.provider = 'gemini' THEN COALESCE(n.req_json->>'model', n.resp_json->>'model')
                WHEN n.provider = 'claude-code' THEN COALESCE(n.req_json->>'model', n.resp_json->>'model')
            END AS model,
            CASE
                WHEN n.provider = 'gemini' THEN n.resp_json->>'modelVersion'
                WHEN n.provider = 'claude-code' THEN n.resp_json->>'model'
            END AS model_version,
            CASE
                WHEN n.provider = 'gemini'
                    THEN COALESCE(n.resp_json->>'finishReason', n.resp_json #>> '{candidates,0,finishReason}', 'completed')
                WHEN n.provider = 'claude-code'
                    THEN COALESCE(n.resp_json->>'stop_reason', n.resp_json->>'finish_reason', n.resp_json->>'type', 'completed')
            END AS status,
            CASE
                WHEN n.provider = 'gemini' THEN n.resp_json->>'corrId'
                ELSE NULL
            END AS corr_id,
            CASE
                WHEN n.provider = 'gemini' THEN n.req_json->'contents'
                WHEN n.provider = 'claude-code' THEN n.req_json->'messages'
            END AS prompt_json,
            CASE
                WHEN n.provider = 'gemini' THEN n.resp_json->'candidates'
                WHEN n.provider = 'claude-code' THEN n.resp_json->'content'
            END AS response_json,
            CASE
                WHEN n.provider = 'gemini' THEN jsonb_strip_nulls(
                    COALESCE(n.resp_json->'usageMetadata', '{}'::jsonb) ||
                    jsonb_build_object(
                        'cachedContentTokenCount', n.resp_json->'cachedContentTokenCount',
                        'cacheTokensDetails', n.resp_json->'cacheTokensDetails'
                    )
                )
                WHEN n.provider = 'claude-code' THEN n.resp_json->'usage'
            END AS usage_json,
            CASE
                WHEN n.provider = 'gemini' THEN jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.candidates[*].content.parts[*].functionCall')
                WHEN n.provider = 'claude-code' THEN
                    -- Check if OpenAI format has results, otherwise use Anthropic format
                    CASE
                        WHEN jsonb_array_length(jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.content[*].tool_calls[*]')) > 0
                            THEN jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.content[*].tool_calls[*]')
                        ELSE jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.content[*]?(@.type == "tool_use")')
                    END
            END AS tool_calls_json
        FROM normalized n
        WHERE (
            (n.provider = 'gemini' AND n.resp_json ? 'responseId') OR
            (n.provider = 'claude-code' AND (n.resp_json ? 'content' OR n.resp_json ? 'delta'))
        )
    ),
    upsert_main AS (
        INSERT INTO llm_http_event (
            host, http_response_id, http_request_id, response_key, provider, model, model_version,
            status, corr_id, prompt, response, usage, raw_request, raw_response,
            started_at, ended_at, exec_id, root_exec_id, root_pid
        )
        SELECT
            p.host,
            p.response_id,
            p.http_request_id,
            p.response_key,
            p.provider,
            p.model,
            p.model_version,
            p.status,
            p.corr_id,
            p.prompt_json,
            p.response_json,
            p.usage_json,
            p.raw_request,
            p.raw_response,
            p.response_ts,
            p.response_ts,
            p.exec_id,
            p.root_exec_id,
            p.root_pid
        FROM prepared p
        WHERE p.response_key IS NOT NULL
        ON CONFLICT (host, http_response_id) DO UPDATE
        SET response_key = EXCLUDED.response_key,
            provider = EXCLUDED.provider,
            http_request_id = COALESCE(EXCLUDED.http_request_id, llm_http_event.http_request_id),
            model = COALESCE(EXCLUDED.model, llm_http_event.model),
            model_version = COALESCE(EXCLUDED.model_version, llm_http_event.model_version),
            status = EXCLUDED.status,
            corr_id = COALESCE(EXCLUDED.corr_id, llm_http_event.corr_id),
            prompt = COALESCE(EXCLUDED.prompt, llm_http_event.prompt),
            response = COALESCE(EXCLUDED.response, llm_http_event.response),
            usage = COALESCE(EXCLUDED.usage, llm_http_event.usage),
            raw_request = COALESCE(EXCLUDED.raw_request, llm_http_event.raw_request),
            raw_response = COALESCE(EXCLUDED.raw_response, llm_http_event.raw_response),
            started_at = LEAST(COALESCE(llm_http_event.started_at, EXCLUDED.started_at), EXCLUDED.started_at),
            ended_at = GREATEST(COALESCE(llm_http_event.ended_at, EXCLUDED.ended_at), EXCLUDED.ended_at),
            exec_id = COALESCE(EXCLUDED.exec_id, llm_http_event.exec_id),
            root_exec_id = COALESCE(EXCLUDED.root_exec_id, llm_http_event.root_exec_id),
            root_pid = COALESCE(EXCLUDED.root_pid, llm_http_event.root_pid)
        RETURNING host, response_key, provider, http_response_id
    ),
    tool_payload AS (
        SELECT
            u.host,
            u.response_key,
            u.provider,
            jsonb_array_elements(p.tool_calls_json) AS tool_obj
        FROM upsert_main u
        JOIN prepared p
            ON p.host = u.host AND p.response_id = u.http_response_id
        WHERE p.tool_calls_json IS NOT NULL
            AND jsonb_array_length(p.tool_calls_json) > 0
    )
    INSERT INTO llm_tool_call_event(host, response_key, tool_call_id, name, arguments, provider)
    SELECT
        t.host,
        t.response_key,
        COALESCE(t.tool_obj->>'id', t.tool_obj->>'toolCallId', md5(t.tool_obj::text)),
        COALESCE(t.tool_obj->>'name', t.tool_obj #>> '{functionCall,name}', t.tool_obj->>'function'),
        COALESCE(
            t.tool_obj->'arguments',
            t.tool_obj #> '{functionCall,arguments}',
            t.tool_obj->'args'
        ),
        t.provider
    FROM tool_payload t
    ON CONFLICT (host, response_key, tool_call_id) DO UPDATE
    SET name = EXCLUDED.name,
        arguments = COALESCE(EXCLUDED.arguments, llm_tool_call_event.arguments),
        provider = EXCLUDED.provider;

    GET DIAGNOSTICS v_rows = ROW_COUNT;

    RETURN v_rows;
END;
$$;

-- Agent threat reports table
-- Stores threat insights reported by AI agents (Claude Code, etc.)
-- This allows agents to proactively report threats they detect during execution
CREATE TABLE IF NOT EXISTS agent_threat_reports (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Identifiers
    host TEXT NOT NULL,
    root_exec_id TEXT,

    -- Agent information
    agent_type TEXT NOT NULL,           -- e.g., 'claude-code', 'gemini', 'custom'
    agent_version TEXT,                  -- agent version if available
    session_id TEXT,                     -- agent session ID for correlation

    -- Threat information
    threat_type TEXT NOT NULL,           -- e.g., 'malicious_code', 'prompt_injection', 'data_exfiltration'
    threat_level INTEGER NOT NULL,       -- 1-5 scale (1=low, 5=critical)
    confidence REAL NOT NULL DEFAULT 0.5, -- 0.0-1.0

    -- Agent's analysis
    title TEXT NOT NULL,                 -- brief title of the threat
    description TEXT,                    -- detailed description
    evidence JSONB,                      -- agent-provided evidence (flexible schema)

    -- Context
    detection_method TEXT,               -- how the agent detected this (e.g., 'code_analysis', 'behavior_monitoring')
    file_path TEXT,                      -- relevant file path if applicable
    code_snippet TEXT,                   -- relevant code snippet if applicable

    -- Status
    status TEXT NOT NULL DEFAULT 'active', -- 'active', 'acknowledged', 'false_positive', 'resolved'
    reviewed_at TIMESTAMPTZ,
    reviewed_by TEXT,

    -- Metadata
    metadata JSONB                       -- additional agent-specific data
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_root_exec_id
    ON agent_threat_reports(root_exec_id) WHERE root_exec_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_session_id
    ON agent_threat_reports(session_id) WHERE session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_host
    ON agent_threat_reports(host);

CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_status
    ON agent_threat_reports(status);

CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_threat_level
    ON agent_threat_reports(threat_level);

CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_created_at
    ON agent_threat_reports(created_at DESC);

-- Composite index for active threat lookup
CREATE INDEX IF NOT EXISTS idx_agent_threat_reports_active_lookup
    ON agent_threat_reports(root_exec_id, threat_level, created_at DESC)
    WHERE status = 'active';

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_agent_threat_reports_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_agent_threat_reports_updated_at ON agent_threat_reports;
CREATE TRIGGER trigger_update_agent_threat_reports_updated_at
    BEFORE UPDATE ON agent_threat_reports
    FOR EACH ROW
    EXECUTE FUNCTION update_agent_threat_reports_updated_at();

-- Helper function to insert or update agent threat report
CREATE OR REPLACE FUNCTION upsert_agent_threat_report(
    p_host TEXT,
    p_root_exec_id TEXT,
    p_agent_type TEXT,
    p_agent_version TEXT,
    p_session_id TEXT,
    p_threat_type TEXT,
    p_threat_level INTEGER,
    p_confidence REAL,
    p_title TEXT,
    p_description TEXT,
    p_evidence JSONB,
    p_detection_method TEXT,
    p_file_path TEXT,
    p_code_snippet TEXT,
    p_metadata JSONB
) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE
    v_report_id UUID;
    v_exists INTEGER;
BEGIN
    -- Check if a similar active report already exists (same host, session, threat_type)
    SELECT COUNT(*) INTO v_exists
    FROM agent_threat_reports
    WHERE host = p_host
      AND COALESCE(session_id, '') = COALESCE(p_session_id, '')
      AND COALESCE(root_exec_id, '') = COALESCE(p_root_exec_id, '')
      AND threat_type = p_threat_type
      AND status = 'active'
      AND created_at > now() - interval '1 hour';

    IF v_exists > 0 THEN
        -- Update existing report
        UPDATE agent_threat_reports
        SET
            agent_version = p_agent_version,
            threat_level = GREATEST(agent_threat_reports.threat_level, p_threat_level),
            confidence = GREATEST(agent_threat_reports.confidence, p_confidence),
            title = p_title,
            description = COALESCE(p_description, agent_threat_reports.description),
            evidence = COALESCE(p_evidence, agent_threat_reports.evidence),
            detection_method = p_detection_method,
            file_path = COALESCE(p_file_path, agent_threat_reports.file_path),
            code_snippet = COALESCE(p_code_snippet, agent_threat_reports.code_snippet),
            metadata = COALESCE(p_metadata, agent_threat_reports.metadata)
        WHERE host = p_host
          AND COALESCE(session_id, '') = COALESCE(p_session_id, '')
          AND COALESCE(root_exec_id, '') = COALESCE(p_root_exec_id, '')
          AND threat_type = p_threat_type
          AND status = 'active'
          AND created_at > now() - interval '1 hour'
        RETURNING id INTO v_report_id;
    ELSE
        -- Insert new report
        INSERT INTO agent_threat_reports (
            host, root_exec_id, agent_type, agent_version, session_id,
            threat_type, threat_level, confidence, title, description,
            evidence, detection_method, file_path, code_snippet, metadata
        ) VALUES (
            p_host, p_root_exec_id, p_agent_type, p_agent_version, p_session_id,
            p_threat_type, p_threat_level, p_confidence, p_title, p_description,
            p_evidence, p_detection_method, p_file_path, p_code_snippet, p_metadata
        )
        RETURNING id INTO v_report_id;
    END IF;

    RETURN v_report_id;
END;
$$;

-- Query for fetching agent threat reports by root_exec_id
CREATE OR REPLACE FUNCTION get_agent_threat_reports_by_root_exec_id(p_root_exec_id TEXT)
RETURNS TABLE (
    id UUID,
    created_at TIMESTAMPTZ,
    host TEXT,
    root_exec_id TEXT,
    agent_type TEXT,
    agent_version TEXT,
    session_id TEXT,
    threat_type TEXT,
    threat_level INTEGER,
    confidence REAL,
    title TEXT,
    description TEXT,
    evidence JSONB,
    detection_method TEXT,
    file_path TEXT,
    code_snippet TEXT,
    status TEXT
) LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY
    SELECT
        atr.id,
        atr.created_at,
        atr.host,
        atr.root_exec_id,
        atr.agent_type,
        atr.agent_version,
        atr.session_id,
        atr.threat_type,
        atr.threat_level,
        atr.confidence,
        atr.title,
        atr.description,
        atr.evidence,
        atr.detection_method,
        atr.file_path,
        atr.code_snippet,
        atr.status
    FROM agent_threat_reports atr
    WHERE atr.root_exec_id = p_root_exec_id
      AND atr.status = 'active'
    ORDER BY atr.threat_level DESC, atr.created_at DESC;
END;
$$;

-- Comment for documentation
COMMENT ON TABLE agent_threat_reports IS 'Stores threat insights reported by AI agents during execution';
COMMENT ON COLUMN agent_threat_reports.evidence IS 'Flexible JSONB schema for agent-provided evidence (e.g., code snippets, log excerpts, analysis results)';
COMMENT ON COLUMN agent_threat_reports.status IS 'Report status: active=unreviewed, acknowledged=seen, false_positive=invalid, resolved=handled';
