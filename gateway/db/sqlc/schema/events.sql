CREATE TABLE IF NOT EXISTS http_request (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    tid INTEGER NOT NULL CHECK (tid >= 0),
    uid INTEGER NOT NULL CHECK (uid >= 0),
    gid INTEGER NOT NULL CHECK (gid >= 0),
    comm TEXT NOT NULL,
    method TEXT NOT NULL,
    content_length BIGINT,
    url TEXT NOT NULL,
    protocol TEXT NOT NULL,
    headers JSONB,
    body BYTEA,
    truncated BOOLEAN NOT NULL,
    host TEXT NOT NULL,
    container_id TEXT
);

CREATE TABLE IF NOT EXISTS http_response (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    tid INTEGER NOT NULL CHECK (tid >= 0),
    uid INTEGER NOT NULL CHECK (uid >= 0),
    gid INTEGER NOT NULL CHECK (gid >= 0),
    comm TEXT NOT NULL,
    status_code SMALLINT NOT NULL CHECK (status_code >= 0),
    content_length BIGINT,
    protocol TEXT NOT NULL,
    headers JSONB,
    body BYTEA,
    truncated BOOLEAN NOT NULL,
    host TEXT NOT NULL,
    container_id TEXT
);

CREATE TABLE IF NOT EXISTS exec_events (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    ppid INTEGER NOT NULL CHECK (ppid >= 0),
    exec_id TEXT NOT NULL,
    p_exec_id TEXT NOT NULL,
    cwd TEXT NOT NULL,
    comm TEXT NOT NULL,
    args TEXT NOT NULL,
    host TEXT NOT NULL,
    container_id TEXT
);

CREATE TABLE IF NOT EXISTS mcp_stdio_event (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    host TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    tid INTEGER NOT NULL CHECK (tid >= 0),
    uid INTEGER NOT NULL CHECK (uid >= 0),
    gid INTEGER NOT NULL CHECK (gid >= 0),
    message_type TEXT NOT NULL CHECK (message_type IN ('request','response','notification')),
    jsonrpc TEXT,
    method TEXT,
    params JSONB,
    result JSONB,
    error JSONB,
    corr_id TEXT,
    container_id TEXT
);

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
serverinfo_by_corr_pidset AS (
    SELECT DISTINCT ON (be.host, be.corr_id)
        be.host,
        be.corr_id,
        se.result->'serverInfo'->>'name' AS server_name,
        se.timestamp
    FROM base_events be
    JOIN base_events se
      ON se.host = be.host
     AND se.corr_id = be.corr_id
     AND se.result ? 'serverInfo'
    ORDER BY be.host, be.corr_id, se.timestamp DESC
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
