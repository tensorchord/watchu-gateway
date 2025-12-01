-- Add STDIO MCP ingest storage and normalized view.
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
    corr_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_stdio_host_ts ON mcp_stdio_event(host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_stdio_host_corr ON mcp_stdio_event(host, corr_id);

DROP VIEW IF EXISTS mcp_events_normalized;
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
    headers->>'jsonrpc' AS jsonrpc,
    COALESCE(headers->>'method', headers->>':method') AS method,
    headers AS raw,
    NULL::jsonb AS params,
    NULL::jsonb AS result,
    NULL::jsonb AS error,
    http_id::text AS corr_id
FROM process_http_events
WHERE is_mcp_http
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
