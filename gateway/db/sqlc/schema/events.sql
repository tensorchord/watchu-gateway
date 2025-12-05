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
        phe.exec_id,
        phe.root_exec_id,
        phe.root_pid,
        phe.http_type,
        phe.headers,
        phe.http_id,
        safe_json_from_bytea(phe.body) AS body_json
    FROM process_http_events phe
    WHERE phe.is_mcp_http
)
SELECT
    'http' AS transport,
    host,
    timestamp,
    pid,
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
FROM stdio_enriched;
