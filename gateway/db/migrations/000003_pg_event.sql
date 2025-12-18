-- Add Postgres client protocol event storage.
CREATE TABLE IF NOT EXISTS pg_event (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    host TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER NOT NULL CHECK (pid >= 0),
    tid INTEGER NOT NULL CHECK (tid >= 0),
    uid INTEGER NOT NULL CHECK (uid >= 0),
    gid INTEGER NOT NULL CHECK (gid >= 0),
    comm TEXT,
    msg_type TEXT, -- 'Q' (Query), 'P' (Parse), 'B' (Bind), 'E' (Execute), 'C' (Close), 'X' (Terminate)
    data BYTEA,
    container_id TEXT
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_pg_event_host_ts ON pg_event(host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_pg_event_host_pid_ts ON pg_event(host, pid, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_pg_event_msg_type ON pg_event(msg_type);
CREATE INDEX IF NOT EXISTS idx_pg_event_container_id ON pg_event(container_id) WHERE container_id IS NOT NULL;

-- Comments for documentation
COMMENT ON TABLE pg_event IS 'Postgres frontend messages (client → server) for database observability';
COMMENT ON COLUMN pg_event.msg_type IS 'Postgres protocol message type: Q (Query), P (Parse), B (Bind), E (Execute), C (Close), X (Terminate)';
COMMENT ON COLUMN pg_event.data IS 'Raw message bytes for offline parsing and SQL extraction';
