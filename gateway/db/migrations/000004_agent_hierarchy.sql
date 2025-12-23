-- Agent hierarchy schema, LLM normalization, and upsert routine.

-- Ensure container metadata columns exist on ingest tables.
ALTER TABLE http_request ADD COLUMN IF NOT EXISTS container_id TEXT;
ALTER TABLE http_response ADD COLUMN IF NOT EXISTS container_id TEXT;
ALTER TABLE exec_events ADD COLUMN IF NOT EXISTS container_id TEXT;
ALTER TABLE mcp_stdio_event ADD COLUMN IF NOT EXISTS container_id TEXT;

CREATE OR REPLACE FUNCTION safe_text_from_bytea(p_body BYTEA)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_text TEXT;
BEGIN
    IF p_body IS NULL THEN
        RETURN NULL;
    END IF;
    BEGIN
        v_text := convert_from(p_body, 'UTF8');
    EXCEPTION
        WHEN others THEN
            BEGIN
                -- Best-effort fallback: LATIN1 never errors on arbitrary bytes (except NUL),
                -- which helps extract strings from non-UTF8 payloads (e.g. XML).
                v_text := convert_from(p_body, 'LATIN1');
            EXCEPTION
                WHEN others THEN
                    RETURN NULL;
            END;
    END;
    RETURN v_text;
END;
$$;

CREATE OR REPLACE FUNCTION strip_sse_data(p_text TEXT)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_line TEXT;
    v_last_data TEXT;
    v_response_json TEXT;
BEGIN
    IF p_text IS NULL THEN
        RETURN NULL;
    END IF;

    FOR v_line IN SELECT * FROM regexp_split_to_table(p_text, E'\n') LOOP
        IF v_line ~ '^\s*data:' THEN
            v_line := btrim(substring(v_line FROM '^\s*data:\s*(.*)$'));
            IF v_line IS NOT NULL AND v_line <> '' THEN
                v_last_data := v_line;
                IF POSITION('"responseId"' IN v_line) > 0 THEN
                    v_response_json := v_line;
                END IF;
            END IF;
        END IF;
    END LOOP;

    IF v_response_json IS NOT NULL THEN
        RETURN v_response_json;
    END IF;

    IF v_last_data IS NOT NULL THEN
        RETURN v_last_data;
    END IF;

    RETURN p_text;
END;
$$;

CREATE OR REPLACE FUNCTION safe_json_from_bytea(p_body BYTEA)
RETURNS JSONB LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_text TEXT;
BEGIN
    v_text := strip_sse_data(safe_text_from_bytea(p_body));
    IF v_text IS NULL OR btrim(v_text) = '' THEN
        RETURN NULL;
    END IF;
    BEGIN
        RETURN v_text::jsonb;
    EXCEPTION
        WHEN others THEN
            RETURN NULL;
    END;
END;
$$;

DROP VIEW IF EXISTS mcp_events_normalized;

CREATE VIEW mcp_events_normalized AS
WITH stdio_enriched AS (
    SELECT
        s.host,
        s.timestamp,
        s.pid,
        s.tid,
        l.exec_id,
        l.root_exec_id,
        l.root_pid,
        s.message_type,
        s.jsonrpc,
        s.method,
        s.params,
        s.result,
        s.error,
        s.corr_id
    FROM mcp_stdio_event s
    LEFT JOIN process_lifecycle l
      ON l.host = s.host
     AND l.pid = s.pid
     AND s.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
),
http_enriched AS (
    SELECT
        phe.host,
        phe.timestamp,
        phe.pid,
        phe.tid,
        phe.exec_id,
        phe.root_exec_id,
        phe.root_pid,
        phe.http_type,
        phe.headers,
        phe.http_id,
        safe_json_from_bytea(phe.body) AS body_json
    FROM process_http_events phe
    WHERE phe.is_mcp_http
),
base_events AS (
    SELECT
        'http' AS transport,
        host,
        timestamp,
        pid,
        tid,
        exec_id,
        root_exec_id,
        root_pid,
        CASE WHEN http_type = 'request' THEN 'request' ELSE 'response' END AS message_type,
        COALESCE(body_json->>'jsonrpc', headers->>'jsonrpc') AS jsonrpc,
        COALESCE(body_json->>'method', headers->>'method', headers->>':method') AS method,
        headers AS raw,
        body_json->'params' AS params,
        body_json->'result' AS result,
        body_json->'error' AS error,
        COALESCE(body_json->>'id', headers->>'x-mcp-id', http_id::text) AS corr_id
    FROM http_enriched
    UNION ALL
    SELECT
        'stdio' AS transport,
        host,
        timestamp,
        pid,
        tid,
        exec_id,
        root_exec_id,
        root_pid,
        message_type,
        jsonrpc,
        method,
        NULL::jsonb AS raw,
        params,
        result,
        error,
        corr_id
    FROM stdio_enriched
),
serverinfo_by_tid AS (
    SELECT DISTINCT ON (host, tid)
        host,
        tid,
        result->'serverInfo'->>'name' AS server_name,
        timestamp
    FROM base_events
    WHERE result ? 'serverInfo' AND tid IS NOT NULL
    ORDER BY host, tid, timestamp DESC
),
serverinfo_by_corr AS (
    SELECT DISTINCT ON (host, corr_id)
        host,
        corr_id,
        result->'serverInfo'->>'name' AS server_name,
        timestamp
    FROM base_events
    WHERE result ? 'serverInfo'
    ORDER BY host, corr_id, timestamp DESC
),
serverinfo_by_pid AS (
    SELECT DISTINCT ON (host, pid)
        host,
        pid,
        result->'serverInfo'->>'name' AS server_name,
        timestamp
    FROM base_events
    WHERE result ? 'serverInfo'
    ORDER BY host, pid, timestamp DESC
),
corr_pidset AS (
    SELECT
        host,
        corr_id,
        ARRAY(SELECT DISTINCT pid FROM base_events c2 WHERE c2.host = c.host AND c2.corr_id = c.corr_id) AS pids
    FROM base_events c
    GROUP BY host, corr_id
),
serverinfo_by_corr_pidset AS (
    SELECT DISTINCT ON (ps.host, ps.corr_id)
        ps.host,
        ps.corr_id,
        se.result->'serverInfo'->>'name' AS server_name,
        se.timestamp
    FROM corr_pidset ps
    JOIN base_events se
      ON se.host = ps.host
     AND se.pid = ANY(ps.pids)
     AND se.result ? 'serverInfo'
    ORDER BY ps.host, ps.corr_id, se.timestamp DESC
)
SELECT
    b.transport,
    b.host,
    b.timestamp,
    b.pid,
    b.exec_id,
    b.root_exec_id,
    b.root_pid,
    b.message_type,
    b.jsonrpc,
    b.method,
    b.raw,
    b.params,
    b.result,
    b.error,
    b.corr_id,
    COALESCE(
        (SELECT value FROM jsonb_each_text(b.raw) WHERE lower(key) IN ('x-mcp-server','x-mcp-server-name','x-mcp-name') LIMIT 1),
        b.raw->>'x-mcp-server',
        b.raw->>'x-mcp-server-name',
        b.raw->>'x-mcp-name',
        b.raw->'serverInfo'->>'name',
        b.raw->>'host',
        COALESCE(b.result->'serverInfo'->>'name', b.params->'serverInfo'->>'name'),
        (SELECT server_name FROM serverinfo_by_tid st WHERE st.host = b.host AND st.tid = b.tid AND b.tid IS NOT NULL),
        (SELECT server_name FROM serverinfo_by_pid sp WHERE sp.host = b.host AND sp.pid = b.pid),
        (SELECT server_name FROM serverinfo_by_corr sc WHERE sc.host = b.host AND sc.corr_id = b.corr_id),
        (SELECT server_name FROM serverinfo_by_corr_pidset scp WHERE scp.host = b.host AND scp.corr_id = b.corr_id)
    ) AS server,
    COALESCE(
        b.params->>'name',
        b.params->>'tool_name'
    ) AS tool
FROM base_events b;

CREATE OR REPLACE FUNCTION safe_numeric(p_text TEXT)
RETURNS NUMERIC LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_val NUMERIC;
BEGIN
    IF p_text IS NULL OR btrim(p_text) = '' THEN
        RETURN NULL;
    END IF;
    BEGIN
        v_val := p_text::numeric;
    EXCEPTION
        WHEN others THEN
            RETURN NULL;
    END;
    RETURN v_val;
END;
$$;

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

CREATE INDEX IF NOT EXISTS idx_agent_run_host_started ON agent_run(host, started_at DESC);

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

CREATE INDEX IF NOT EXISTS idx_trace_agent_started
    ON trace(agent_run_id, started_at DESC NULLS LAST);

CREATE UNIQUE INDEX IF NOT EXISTS idx_trace_agent_type_external
    ON trace(agent_run_id, trace_type, external_id, phase);

CREATE TABLE IF NOT EXISTS resource_usage (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    trace_id UUID NOT NULL REFERENCES trace(id) ON DELETE CASCADE,
    metric TEXT NOT NULL,
    value NUMERIC,
    unit TEXT,
    UNIQUE (trace_id, metric)
);
CREATE INDEX IF NOT EXISTS idx_resource_usage_trace ON resource_usage(trace_id);

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
CREATE INDEX IF NOT EXISTS idx_llm_http_event_key ON llm_http_event(host, response_key);

CREATE TABLE IF NOT EXISTS llm_tool_call_event (
    host TEXT NOT NULL,
    response_key TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    name TEXT,
    arguments JSONB,
    provider TEXT,
    PRIMARY KEY (host, response_key, tool_call_id)
);

-- Prompt injection schema extensions
ALTER TABLE llm_prompt_injection_results
    ADD COLUMN IF NOT EXISTS trace_id UUID REFERENCES trace(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS agent_run_id UUID REFERENCES agent_run(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS prompt_hash TEXT,
    ADD COLUMN IF NOT EXISTS score DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS model TEXT,
    ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS metadata JSONB;

ALTER TABLE llm_prompt_injection_results
    ALTER COLUMN request_id SET NOT NULL,
    ALTER COLUMN host SET NOT NULL,
    ALTER COLUMN severity_level SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE llm_prompt_injection_results
        ADD CONSTRAINT llm_prompt_injection_results_pkey PRIMARY KEY (host, request_id);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;
$$;

CREATE INDEX IF NOT EXISTS llm_prompt_injection_results_hash_idx
    ON llm_prompt_injection_results (prompt_hash)
    WHERE prompt_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS prompt_injection_errors (
    host TEXT NOT NULL,
    request_id UUID NOT NULL,
    last_error TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, request_id)
);

CREATE OR REPLACE FUNCTION upsert_agent_hierarchy(
    p_host  TEXT,
    p_since TIMESTAMPTZ,
    p_until TIMESTAMPTZ
) RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    v_runs   INTEGER := 0;
    v_traces INTEGER := 0;
    v_llm    INTEGER := 0;
BEGIN
    WITH root_ranges AS (
        SELECT
            host,
            root_exec_id,
            MAX(root_pid) AS root_pid,
            MIN(start_ts) AS started_at,
            MAX(end_ts) AS ended_at,
            MAX(CASE WHEN exec_id = root_exec_id THEN comm END) AS root_comm,
            CASE
                WHEN MAX(CASE WHEN exec_id = root_exec_id THEN comm END) ILIKE '%gemini%' THEN 'gemini'
                WHEN MAX(CASE WHEN exec_id = root_exec_id THEN comm END) ILIKE '%claude%' THEN 'claude-code'
                WHEN MAX(CASE WHEN exec_id = root_exec_id THEN comm END) ILIKE '%codex%' THEN 'codex'
                ELSE NULL
            END AS provider,
            EXTRACT(EPOCH FROM (COALESCE(MAX(end_ts), p_until) - MIN(start_ts))) AS duration_seconds
        FROM process_lifecycle
        WHERE host = p_host
          AND root_exec_id IS NOT NULL
          AND start_ts <= p_until
          AND COALESCE(end_ts, p_until) >= p_since
        GROUP BY host, root_exec_id
    ),
    filtered_root_ranges AS (
        SELECT *
        FROM root_ranges
        WHERE provider IS NOT NULL
          AND duration_seconds >= 1
    ),
    run_upserts AS (
        INSERT INTO agent_run (host, root_exec_id, root_pid, provider, started_at, ended_at)
        SELECT
            host,
            root_exec_id,
            root_pid,
            provider,
            started_at,
            ended_at
        FROM filtered_root_ranges
        ON CONFLICT (host, root_exec_id) DO UPDATE
        SET provider = COALESCE(agent_run.provider, EXCLUDED.provider),
            started_at = LEAST(agent_run.started_at, EXCLUDED.started_at),
            ended_at = CASE
                WHEN agent_run.ended_at IS NULL THEN EXCLUDED.ended_at
                WHEN EXCLUDED.ended_at IS NULL THEN agent_run.ended_at
                ELSE GREATEST(agent_run.ended_at, EXCLUDED.ended_at)
            END
        RETURNING 1
    )
    SELECT COUNT(*) INTO v_runs FROM run_upserts;

    WITH mcp_corr AS (
        SELECT
            host,
            corr_id,
            MIN(timestamp) AS started_at,
            MAX(timestamp) AS ended_at,
            MAX(root_exec_id) FILTER (WHERE root_exec_id IS NOT NULL) AS root_exec_id,
            BOOL_OR(message_type = 'request') AS has_request,
            BOOL_OR(message_type = 'response') AS has_response,
            MAX(method) FILTER (WHERE method IS NOT NULL) AS method
        FROM mcp_events_normalized
        WHERE host = p_host
          AND timestamp > p_since
          AND timestamp <= p_until
          AND corr_id IS NOT NULL
        GROUP BY host, corr_id
    ),
    resolved AS (
        SELECT
            c.host,
            c.corr_id,
            c.started_at,
            c.ended_at,
            c.has_request,
            c.has_response,
            c.method,
            ar.id AS agent_run_id
        FROM mcp_corr c
        JOIN agent_run ar
          ON ar.host = c.host
         AND ar.root_exec_id = c.root_exec_id
    ),
    trace_upserts AS (
        INSERT INTO trace (
            agent_run_id,
            trace_type,
            source_table,
            source_id,
            external_id,
            model,
            model_version,
            started_at,
            ended_at,
            phase
        )
        SELECT *
        FROM (
            SELECT
                r.agent_run_id,
                'mcp_call'::text,
                'mcp_events_normalized'::text,
                NULL::uuid,
                r.corr_id::text,
                NULL::text,
                NULL::text,
                r.started_at,
                r.started_at,
                COALESCE(NULLIF(r.method, ''), 'default')
            FROM resolved r
            WHERE r.has_request
            UNION ALL
            SELECT
                r.agent_run_id,
                'mcp_call'::text,
                'mcp_events_normalized'::text,
                NULL::uuid,
                r.corr_id::text,
                NULL::text,
                NULL::text,
                r.ended_at,
                r.ended_at,
                CASE
                    WHEN r.method IS NULL OR r.method = '' THEN 'default/response'
                    ELSE r.method || '/response'
                END
            FROM resolved r
            WHERE r.has_response
        ) rows
        ON CONFLICT (agent_run_id, trace_type, external_id, phase) DO UPDATE
        SET started_at = LEAST(trace.started_at, EXCLUDED.started_at),
            ended_at = CASE
                WHEN trace.ended_at IS NULL THEN EXCLUDED.ended_at
                WHEN EXCLUDED.ended_at IS NULL THEN trace.ended_at
                ELSE GREATEST(trace.ended_at, EXCLUDED.ended_at)
            END
        RETURNING 1
    )
    SELECT COUNT(*) INTO v_traces FROM trace_upserts;

    WITH llm_candidates AS (
        SELECT
            e.host,
            e.response_key,
            e.provider,
            e.model,
            e.model_version,
            e.status,
            e.started_at,
            e.ended_at,
            e.root_exec_id,
            e.root_pid,
            e.exec_id,
            e.http_request_id,
            e.http_response_id,
            e.usage
        FROM llm_http_event e
        WHERE e.host = p_host
          AND e.started_at > p_since
          AND e.started_at <= p_until
          AND e.response_key IS NOT NULL
    ),
    llm_resolved AS (
        SELECT
            l.*,
            ar.id AS agent_run_id
        FROM llm_candidates l
        JOIN agent_run ar
          ON ar.host = l.host
         AND ar.root_exec_id = l.root_exec_id
    ),
    llm_response_latest AS (
        SELECT DISTINCT ON (lr.agent_run_id, lr.response_key)
            lr.*
        FROM llm_resolved lr
        WHERE lr.ended_at IS NOT NULL
        ORDER BY lr.agent_run_id, lr.response_key, lr.ended_at DESC NULLS LAST
    ),
    llm_trace_request_inserts AS (
        INSERT INTO trace (
            agent_run_id,
            trace_type,
            source_table,
            source_id,
            external_id,
            model,
            model_version,
            started_at,
            ended_at,
            phase
        )
        SELECT DISTINCT ON (lr.agent_run_id, lr.response_key)
            lr.agent_run_id,
            'llm_call',
            'llm_http_event',
            lr.http_request_id,
            lr.response_key,
            lr.model,
            lr.model_version,
            lr.started_at,
            lr.started_at,
            'request'
        FROM llm_response_latest lr
        ORDER BY lr.agent_run_id, lr.response_key, lr.started_at DESC NULLS LAST
        ON CONFLICT (agent_run_id, trace_type, external_id, phase) DO NOTHING
        RETURNING id, agent_run_id, external_id AS response_key
    ),
    llm_trace_request_updates AS (
        UPDATE trace t
        SET source_table = 'llm_http_event',
            source_id = COALESCE(lr.http_request_id, t.source_id),
            model = COALESCE(lr.model, t.model),
            model_version = COALESCE(lr.model_version, t.model_version),
            started_at = LEAST(COALESCE(t.started_at, lr.started_at), lr.started_at),
            ended_at = GREATEST(COALESCE(t.ended_at, lr.started_at), lr.started_at)
        FROM llm_response_latest lr
        WHERE t.agent_run_id = lr.agent_run_id
          AND t.trace_type = 'llm_call'
          AND t.external_id = lr.response_key
          AND t.phase = 'request'
          AND NOT EXISTS (
                SELECT 1
                FROM llm_trace_request_inserts ins
                WHERE ins.id = t.id
            )
        RETURNING t.id, t.agent_run_id, lr.response_key
    ),
    llm_trace_requests AS (
        SELECT * FROM llm_trace_request_inserts
        UNION
        SELECT * FROM llm_trace_request_updates
    ),
    llm_trace_response_inserts AS (
        INSERT INTO trace (
            agent_run_id,
            trace_type,
            source_table,
            source_id,
            external_id,
            model,
            model_version,
            started_at,
            ended_at,
            phase
        )
        SELECT
            lr.agent_run_id,
            'llm_call',
            'llm_http_event',
            lr.http_response_id,
            lr.response_key,
            lr.model,
            lr.model_version,
            lr.started_at,
            lr.ended_at,
            'response'
        FROM llm_response_latest lr
        ON CONFLICT (agent_run_id, trace_type, external_id, phase) DO NOTHING
        RETURNING id, agent_run_id, external_id AS response_key
    ),
    llm_trace_response_updates AS (
        UPDATE trace t
        SET source_table = 'llm_http_event',
            source_id = lr.http_response_id,
            model = COALESCE(lr.model, t.model),
            model_version = COALESCE(lr.model_version, t.model_version),
            started_at = LEAST(COALESCE(t.started_at, lr.started_at), lr.started_at),
            ended_at = GREATEST(COALESCE(t.ended_at, lr.ended_at), lr.ended_at)
        FROM llm_response_latest lr
        WHERE t.agent_run_id = lr.agent_run_id
          AND t.trace_type = 'llm_call'
          AND t.external_id = lr.response_key
          AND t.phase = 'response'
          AND NOT EXISTS (
                SELECT 1
                FROM llm_trace_response_inserts ins
                WHERE ins.id = t.id
            )
        RETURNING t.id, t.agent_run_id, lr.response_key
    ),
    llm_trace_responses AS (
        SELECT * FROM llm_trace_response_inserts
        UNION
        SELECT * FROM llm_trace_response_updates
    ),
    llm_trace_join AS (
        SELECT
            lt.id,
            lt.agent_run_id,
            lt.response_key,
            lr.usage,
            lr.started_at,
            lr.ended_at
        FROM llm_trace_responses lt
        JOIN llm_response_latest lr
          ON lr.agent_run_id = lt.agent_run_id
         AND lr.response_key = lt.response_key
    ),
    usage_rows AS (
        SELECT DISTINCT ON (trace_id, metric)
            trace_id,
            metric,
            value,
            unit
        FROM (
            SELECT
                lt.id AS trace_id,
                metric,
                value,
                unit
            FROM llm_trace_join lt
            CROSS JOIN LATERAL (
                VALUES
                    ('input_tokens', safe_numeric(COALESCE(lt.usage->>'promptTokenCount', lt.usage->>'input_tokens', lt.usage->>'prompt_tokens')), 'tokens'),
                    ('output_tokens', safe_numeric(COALESCE(lt.usage->>'candidatesTokenCount', lt.usage->>'output_tokens', lt.usage->>'completion_tokens')), 'tokens'),
                    ('total_tokens', safe_numeric(COALESCE(lt.usage->>'totalTokenCount', lt.usage->>'total_tokens')), 'tokens'),
                    ('cached_input_tokens', safe_numeric(COALESCE(lt.usage->>'cachedContentTokenCount', lt.usage->>'cache_read_input_tokens')), 'tokens')
            ) AS u(metric, value, unit)
            WHERE u.value IS NOT NULL
        ) dedup
        ORDER BY trace_id, metric
    ),
    usage_upsert AS (
        INSERT INTO resource_usage(trace_id, metric, value, unit)
        SELECT trace_id, metric, value, unit FROM usage_rows
        ON CONFLICT (trace_id, metric) DO UPDATE
        SET value = EXCLUDED.value,
            unit  = EXCLUDED.unit
        RETURNING 1
    ),
    tool_candidates AS (
        SELECT
            t.host,
            t.response_key,
            t.tool_call_id,
            t.name,
            t.arguments,
            e.root_exec_id,
            e.root_pid,
            e.started_at,
            e.ended_at
        FROM llm_tool_call_event t
        JOIN llm_http_event e
          ON e.host = t.host AND e.response_key = t.response_key
        WHERE e.host = p_host
          AND e.started_at > p_since
          AND e.started_at <= p_until
    ),
    tool_dedup AS (
        SELECT DISTINCT ON (tc.response_key, tc.tool_call_id)
            tc.*
        FROM tool_candidates tc
        ORDER BY tc.response_key, tc.tool_call_id, tc.started_at DESC NULLS LAST
    ),
    tool_resolved AS (
        SELECT
            tc.*,
            lt.agent_run_id,
            lt.id AS parent_trace_id
        FROM tool_dedup tc
        JOIN llm_trace_responses lt
          ON lt.response_key = tc.response_key
    ),
    tool_resolved_dedup AS (
        SELECT DISTINCT ON (tr.agent_run_id, tr.tool_call_id)
            tr.*
        FROM tool_resolved tr
        ORDER BY tr.agent_run_id, tr.tool_call_id, tr.started_at DESC NULLS LAST
    ),
    tool_cleanup AS (
        DELETE FROM trace t
        USING tool_resolved_dedup tr
        WHERE t.agent_run_id = tr.agent_run_id
          AND t.trace_type = 'tool_use'
          AND t.external_id = tr.tool_call_id
          AND t.phase = 'default'
        RETURNING 1
    ),
    tool_trace_start AS (
        INSERT INTO trace (
            agent_run_id,
            parent_trace_id,
            trace_type,
            source_table,
            source_id,
            external_id,
            model,
            model_version,
            started_at,
            ended_at,
            phase
        )
        SELECT
            tr.agent_run_id,
            tr.parent_trace_id,
            'tool_use',
            'llm_tool_call_event',
            NULL,
            tr.tool_call_id,
            NULL,
            NULL,
            tr.started_at,
            tr.started_at,
            'start'
        FROM tool_resolved_dedup tr
        ON CONFLICT (agent_run_id, trace_type, external_id, phase) DO UPDATE
        SET parent_trace_id = COALESCE(trace.parent_trace_id, EXCLUDED.parent_trace_id),
            started_at = LEAST(COALESCE(trace.started_at, EXCLUDED.started_at), EXCLUDED.started_at),
            ended_at = GREATEST(COALESCE(trace.ended_at, EXCLUDED.ended_at), EXCLUDED.ended_at)
        RETURNING 1
    ),
    tool_trace_end AS (
        INSERT INTO trace (
            agent_run_id,
            parent_trace_id,
            trace_type,
            source_table,
            source_id,
            external_id,
            model,
            model_version,
            started_at,
            ended_at,
            phase
        )
        SELECT
            tr.agent_run_id,
            tr.parent_trace_id,
            'tool_use',
            'llm_tool_call_event',
            NULL,
            tr.tool_call_id,
            NULL,
            NULL,
            tr.ended_at,
            tr.ended_at,
            'end'
        FROM tool_resolved_dedup tr
        WHERE tr.ended_at IS NOT NULL
        ON CONFLICT (agent_run_id, trace_type, external_id, phase) DO UPDATE
        SET parent_trace_id = COALESCE(trace.parent_trace_id, EXCLUDED.parent_trace_id),
            started_at = LEAST(COALESCE(trace.started_at, EXCLUDED.started_at), EXCLUDED.started_at),
            ended_at = GREATEST(COALESCE(trace.ended_at, EXCLUDED.ended_at), EXCLUDED.ended_at)
        RETURNING 1
    ),
    llm_trace_request_count AS (
        SELECT COUNT(*) AS cnt FROM llm_trace_requests
    ),
    llm_trace_response_count AS (
        SELECT COUNT(*) AS cnt FROM llm_trace_responses
    )
    SELECT COALESCE((SELECT cnt FROM llm_trace_request_count), 0) +
           COALESCE((SELECT cnt FROM llm_trace_response_count), 0)
      INTO v_llm;

    RETURN COALESCE(v_runs, 0) + COALESCE(v_traces, 0) + COALESCE(v_llm, 0);
END;
$$;

CREATE OR REPLACE FUNCTION populate_llm_http_events(
    p_host  TEXT,
    p_since TIMESTAMPTZ,
    p_until TIMESTAMPTZ
) RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    v_rows INTEGER := 0;
BEGIN
    WITH src AS (
        SELECT
            rl.host,
            rl.response_id,
            rl.response_ts,
            rl.exec_id,
            rl.root_exec_id,
            rl.root_pid,
            req_match.id AS http_request_id,
            safe_json_from_bytea(rl.request_body)  AS req_json,
            safe_json_from_bytea(rl.response_body) AS resp_json,
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
                WHEN n.provider = 'claude-code' THEN jsonb_path_query_array(COALESCE(n.resp_json, '{}'::jsonb), '$.content[*].tool_calls[*]')
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

-- Add reason columns to support LLM-generated explanations for high-risk detections.

-- Add reason column to llm_prompt_injection_results
ALTER TABLE llm_prompt_injection_results ADD COLUMN IF NOT EXISTS reason TEXT;

-- Add reason column to heuristic_alerts
ALTER TABLE heuristic_alerts ADD COLUMN IF NOT EXISTS reason TEXT;

-- Add comments to document the purpose
COMMENT ON COLUMN llm_prompt_injection_results.reason IS 'LLM-generated explanation for why this prompt was classified as unsafe or controversial';
COMMENT ON COLUMN heuristic_alerts.reason IS 'Explanation for why this alert was triggered';

-- Performance optimization: Add index for timeline queries
-- These indexes optimize the common query pattern: WHERE host = X AND timestamp >= Y AND timestamp <= Z ORDER BY timestamp DESC
CREATE INDEX IF NOT EXISTS idx_pl_host_start_ts_desc ON process_lifecycle(host, start_ts DESC);
CREATE INDEX IF NOT EXISTS idx_phe_host_ts_desc ON process_http_events(host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_exec_events_host_exec_id ON exec_events(host, exec_id);
CREATE INDEX IF NOT EXISTS idx_exec_events_host_p_exec_id ON exec_events(host, p_exec_id);
CREATE INDEX IF NOT EXISTS idx_exec_events_host_pid ON exec_events(host, pid);
CREATE INDEX IF NOT EXISTS idx_exec_events_host_ppid ON exec_events(host, ppid);

-- Derived Postgres client events enriched with process lifecycle metadata.

-- strip_cstring_terminator trims the first NULL byte (0x00) and everything after it.
-- This is required because Postgres text values cannot contain 0x00, while the wire
-- protocol often uses C-strings (NUL-terminated).
CREATE OR REPLACE FUNCTION strip_cstring_terminator(p_data BYTEA)
RETURNS BYTEA
LANGUAGE sql
IMMUTABLE
AS $$
    -- NOTE:
    -- - Postgres does not provide strpos(bytea, bytea). Use a hex view to locate the first 0x00.
    -- - Avoid E'\\x00' which can embed a NUL in a text literal and fail under UTF-8 client encodings.
    SELECT CASE
        WHEN p_data IS NULL THEN NULL
        ELSE (
            SELECT CASE
                WHEN s.pos > 0 THEN substring(p_data FROM 1 FOR ((s.pos - 1) / 2))
                ELSE p_data
            END
            FROM (SELECT strpos(encode(p_data, 'hex'), '00') AS pos) s
        )
    END;
$$;

-- process_pg_events is a derived table that adds exec/root context and decodes SQL
-- for simple query messages (msg_type='Q').
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

CREATE INDEX IF NOT EXISTS idx_process_pg_events_host_ts ON process_pg_events(host, timestamp);
CREATE INDEX IF NOT EXISTS idx_process_pg_events_host_pid_ts ON process_pg_events(host, pid, timestamp);
CREATE INDEX IF NOT EXISTS idx_process_pg_events_host_root_ts ON process_pg_events(host, root_exec_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_process_pg_events_sql_hash ON process_pg_events(sql_hash) WHERE sql_hash IS NOT NULL;

COMMENT ON TABLE process_pg_events IS 'Postgres client events enriched with process lifecycle (exec/root) and decoded SQL for Q messages';
COMMENT ON COLUMN process_pg_events.sql_text IS 'Decoded SQL text for msg_type=Q (NUL-terminated bytes trimmed before UTF-8 decode)';
COMMENT ON COLUMN process_pg_events.sql_hash IS 'Hash of normalized sql_text for grouping/top queries';

-- Derived S3 access events enriched with process lifecycle metadata.
-- A single S3 response is treated as one "access record" because status_code and
-- x-amz-request-id are best observed on the response side. The gateway derivation
-- microbatch links the nearest request (same host+pid) to recover method/url and
-- extract bucket/object_key when possible.
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

ALTER TABLE process_s3_events
    ADD COLUMN IF NOT EXISTS bucket_region TEXT;

CREATE INDEX IF NOT EXISTS idx_process_s3_events_host_ts ON process_s3_events(host, timestamp);
CREATE INDEX IF NOT EXISTS idx_process_s3_events_host_root_ts ON process_s3_events(host, root_exec_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_process_s3_events_host_bucket_ts ON process_s3_events(host, bucket, timestamp) WHERE bucket IS NOT NULL AND bucket <> '';
CREATE INDEX IF NOT EXISTS idx_process_s3_events_status_code ON process_s3_events(status_code);

COMMENT ON TABLE process_s3_events IS 'S3 access events derived from client HTTP telemetry and enriched with process lifecycle (exec/root)';
COMMENT ON COLUMN process_s3_events.operation IS 'S3 API operation type inferred from response (PutObject, GetObject, ListObjectsV2, DeleteObject, HeadObject)';
