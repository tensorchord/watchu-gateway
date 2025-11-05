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
    host TEXT NOT NULL
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
    host TEXT NOT NULL
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
    host TEXT NOT NULL
);