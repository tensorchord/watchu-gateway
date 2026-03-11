-- Propagate collector-generated trace IDs through HTTP ingestion and use them
-- as the single request-response correlation key.

ALTER TABLE http_request
    ADD COLUMN IF NOT EXISTS trace_id TEXT;

ALTER TABLE http_response
    ADD COLUMN IF NOT EXISTS trace_id TEXT;

CREATE INDEX IF NOT EXISTS idx_http_request_trace_id
    ON http_request (trace_id);

CREATE INDEX IF NOT EXISTS idx_http_response_trace_id
    ON http_response (trace_id);

CREATE OR REPLACE FUNCTION populate_llm_http_events(
    p_host  TEXT,
    p_since TIMESTAMPTZ,
    p_until TIMESTAMPTZ
) RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    v_rows INTEGER := 0;
BEGIN
    WITH windowed_response AS (
        SELECT
            r.host,
            r.id AS response_id,
            r.timestamp AS response_ts,
            r.pid,
            r.trace_id,
            r.body AS response_body
        FROM http_response r
        WHERE r.host = p_host
          AND r.timestamp > p_since
          AND r.timestamp <= p_until
    ),
    response_enriched AS (
        SELECT
            wr.host,
            wr.response_id,
            wr.response_ts,
            wr.pid,
            wr.trace_id,
            wr.response_body,
            pl.exec_id,
            pl.root_exec_id,
            pl.root_pid
        FROM windowed_response wr
        JOIN process_lifecycle pl
            ON pl.host::text = wr.host
            AND pl.pid = wr.pid
            AND wr.response_ts >= pl.start_ts
            AND wr.response_ts <= (pl.end_ts + analyze_idle_timeout())
    ),
    src AS (
        SELECT DISTINCT ON (re.response_id)
            re.host,
            re.response_id,
            re.response_ts,
            re.exec_id,
            re.root_exec_id,
            re.root_pid,
            re.pid,
            re.trace_id,
            req_match.id AS http_request_id,
            safe_json_from_bytea(req_match.body) AS req_json,
            NULLIF(strip_sse_data(safe_text_from_bytea(re.response_body)), '')::jsonb AS resp_json,
            safe_text_from_bytea(req_match.body) AS raw_request,
            safe_text_from_bytea(re.response_body) AS raw_response
        FROM response_enriched re
        LEFT JOIN LATERAL (
            SELECT req.id, req.body
            FROM http_request req
            WHERE req.trace_id = re.trace_id
            LIMIT 1
        ) AS req_match ON TRUE
        ORDER BY re.response_id, re.response_ts
    ),
    normalized AS (
        SELECT
            s.*,
            CASE
                WHEN s.resp_json ? 'responseId' THEN 'gemini'
                WHEN COALESCE(s.resp_json->>'type', '') LIKE 'message%' THEN 'claude-code'
                WHEN s.req_json->>'model' ~ '^(gpt-|codex-|o1-|o3-)' THEN 'codex'
                WHEN (s.resp_json ? 'id' AND s.resp_json->>'id' LIKE 'chatcmpl-%')
                     OR (s.resp_json ? 'choices' AND s.resp_json ? 'model')
                THEN 'codex'
                ELSE NULL
            END AS provider
        FROM src s
        WHERE s.resp_json IS NOT NULL OR s.req_json IS NOT NULL
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
                WHEN n.provider = 'codex' THEN COALESCE(n.resp_json->>'id', 'req-' || md5(n.raw_request))
            END AS response_key,
            CASE
                WHEN n.provider = 'gemini' THEN COALESCE(n.req_json->>'model', n.resp_json->>'model')
                WHEN n.provider = 'claude-code' THEN COALESCE(n.req_json->>'model', n.resp_json->>'model')
                WHEN n.provider = 'codex' THEN COALESCE(n.req_json->>'model', n.resp_json->>'model')
            END AS model,
            CASE
                WHEN n.provider = 'gemini' THEN n.resp_json->>'modelVersion'
                WHEN n.provider = 'claude-code' THEN n.resp_json->>'model'
                WHEN n.provider = 'codex' THEN n.resp_json->>'model'
            END AS model_version,
            CASE
                WHEN n.provider = 'gemini'
                    THEN COALESCE(n.resp_json->>'finishReason', n.resp_json #>> '{candidates,0,finishReason}', 'completed')
                WHEN n.provider = 'claude-code'
                    THEN COALESCE(n.resp_json->>'stop_reason', n.resp_json->>'finish_reason', n.resp_json->>'type', 'completed')
                WHEN n.provider = 'codex'
                    THEN COALESCE(n.resp_json #>> '{choices,0,finish_reason}', 'stop')
            END AS status,
            CASE
                WHEN n.provider = 'gemini' THEN n.resp_json->>'corrId'
                ELSE NULL
            END AS corr_id,
            CASE
                WHEN n.provider = 'gemini' THEN n.req_json->'contents'
                WHEN n.provider = 'claude-code' THEN n.req_json->'messages'
                WHEN n.provider = 'codex' THEN COALESCE(n.req_json->'messages', jsonb_build_array(jsonb_build_object('content', n.req_json->>'text')))
            END AS prompt_json,
            CASE
                WHEN n.provider = 'gemini' THEN n.resp_json->'candidates'
                WHEN n.provider = 'claude-code' THEN n.resp_json->'content'
                WHEN n.provider = 'codex' THEN n.resp_json->'choices'
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
                WHEN n.provider = 'codex' THEN n.resp_json->'usage'
            END AS usage_json,
            CASE
                WHEN n.provider = 'gemini' THEN jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.candidates[*].content.parts[*].functionCall')
                WHEN n.provider = 'claude-code' THEN
                    CASE
                        WHEN jsonb_array_length(jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.content[*].tool_calls[*]')) > 0
                            THEN jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.content[*].tool_calls[*]')
                        ELSE jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.content[*]?(@.type == "tool_use")')
                    END
                WHEN n.provider = 'codex' THEN jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.choices[*].message.tool_calls[*]')
            END AS tool_calls_json
        FROM normalized n
        WHERE (
            (n.provider = 'gemini' AND n.resp_json ? 'responseId') OR
            (n.provider = 'claude-code' AND (n.resp_json ? 'content' OR n.resp_json ? 'delta')) OR
            (n.provider = 'codex' AND n.req_json ? 'model')
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
        COALESCE(
            t.tool_obj->>'name',
            t.tool_obj #>> '{functionCall,name}',
            t.tool_obj->>'function',
            t.tool_obj #>> '{function,name}'
        ),
        COALESCE(
            t.tool_obj->'arguments',
            t.tool_obj #> '{functionCall,arguments}',
            t.tool_obj->'args',
            t.tool_obj->'input',
            t.tool_obj #> '{function,arguments}'
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