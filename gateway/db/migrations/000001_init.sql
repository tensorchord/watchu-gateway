-- Core ingestion tables
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
    p_exec_id TEXT,
    cwd TEXT NOT NULL,
    comm TEXT NOT NULL,
    args TEXT NOT NULL,
    host TEXT NOT NULL
);

-- Optional host-focused indexes
DO $$
BEGIN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_exec_events_host_ts ON exec_events(host, timestamp)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_http_request_host_ts ON http_request(host, timestamp)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_http_response_host_ts ON http_response(host, timestamp)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_http_request_headers_gin ON http_request USING gin (headers jsonb_path_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_http_response_headers_gin ON http_response USING gin (headers jsonb_path_ops)';
END$$;

-- Settings: idle timeout (referenced by lifecycle-aware views)
CREATE TABLE IF NOT EXISTS analyze_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        idle_timeout_minutes INTEGER DEFAULT 30
);

INSERT INTO analyze_settings(id, idle_timeout_minutes)
VALUES (1, 30)
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION analyze_idle_timeout()
RETURNS interval LANGUAGE sql STABLE AS $$
    SELECT make_interval(mins => COALESCE((SELECT idle_timeout_minutes FROM analyze_settings WHERE id = 1), 30));
$$;

-- Realtime lifecycle table maintained incrementally
CREATE TABLE IF NOT EXISTS process_lifecycle (
    host          varchar NOT NULL,
    exec_id       varchar NOT NULL,
    p_exec_id     varchar,
    pid           bigint,
    ppid          bigint,
    root_exec_id  varchar,
    root_pid      bigint,
    depth         integer,
    start_ts      timestamptz,
    end_ts        timestamptz,
    cwd           varchar,
    comm          varchar,
    args          varchar,
    PRIMARY KEY (host, exec_id)
);
CREATE INDEX IF NOT EXISTS idx_pl_host_pid_start ON process_lifecycle(host, pid, start_ts);
CREATE INDEX IF NOT EXISTS idx_pl_host_root ON process_lifecycle(host, root_exec_id);

-- Incremental upsert of lifecycle from exec_events within a time window
CREATE OR REPLACE FUNCTION refresh_process_lifecycle_incremental(
    p_host  varchar,
    p_since timestamptz,
    p_until timestamptz DEFAULT now()
) RETURNS integer LANGUAGE plpgsql AS $$
DECLARE v_rows integer := 0;
BEGIN
  WITH candidates AS (
      SELECT DISTINCT host, exec_id
      FROM exec_events
      WHERE host = p_host
        AND timestamp BETWEEN p_since AND p_until
  ),
  ascend AS (
      SELECT
          e.host,
          e.exec_id,
          e.p_exec_id,
          e.pid,
          e.ppid,
          e.cwd,
          e.comm,
          e.args,
          e.timestamp AS start_ts,
          e.timestamp AS end_ts,
          e.exec_id AS current_root_exec_id,
          e.pid     AS current_root_pid,
          0 AS depth,
          e.exec_id AS leaf_exec_id
      FROM exec_events e
      JOIN candidates c ON c.host = e.host AND c.exec_id = e.exec_id
      UNION ALL
      SELECT
          parent.host,
          parent.exec_id,
          parent.p_exec_id,
          parent.pid,
          parent.ppid,
          parent.cwd,
          parent.comm,
          parent.args,
          parent.timestamp AS start_ts,
          parent.timestamp AS end_ts,
          parent.exec_id AS current_root_exec_id,
          parent.pid     AS current_root_pid,
          a.depth + 1,
          a.leaf_exec_id
      FROM exec_events parent
      JOIN ascend a
        ON parent.host = a.host
       AND (
              a.p_exec_id = parent.exec_id
           OR (a.ppid = parent.pid AND a.p_exec_id IS NULL)
       )
  ),
  root_pick AS (
      SELECT host, leaf_exec_id,
             max(depth) AS max_depth,
             (ARRAY_AGG(current_root_exec_id ORDER BY depth DESC))[1] AS root_exec_id,
             (ARRAY_AGG(current_root_pid ORDER BY depth DESC))[1]     AS root_pid
      FROM ascend
      GROUP BY host, leaf_exec_id
  ),
  leaf_pick AS (
      SELECT host, exec_id AS leaf_exec_id, p_exec_id, pid, ppid, cwd, comm, args,
             start_ts, end_ts,
             max(depth) OVER (PARTITION BY host, exec_id) AS leaf_depth
      FROM ascend
      WHERE depth = 0
  ),
  ins AS (
      INSERT INTO process_lifecycle AS pl (
          host, exec_id, p_exec_id, pid, ppid,
          root_exec_id, root_pid, depth, start_ts, end_ts,
          cwd, comm, args
      )
      SELECT
          l.host,
          l.leaf_exec_id AS exec_id,
          l.p_exec_id,
          l.pid,
          l.ppid,
          r.root_exec_id,
          r.root_pid,
          COALESCE(r.max_depth, l.leaf_depth),
          l.start_ts,
          l.end_ts,
          l.cwd,
          l.comm,
          l.args
      FROM leaf_pick l
      JOIN root_pick r ON r.host = l.host AND r.leaf_exec_id = l.leaf_exec_id
      ON CONFLICT (host, exec_id) DO UPDATE
      SET p_exec_id    = EXCLUDED.p_exec_id,
          pid          = EXCLUDED.pid,
          ppid         = EXCLUDED.ppid,
          root_exec_id = EXCLUDED.root_exec_id,
          root_pid     = EXCLUDED.root_pid,
          depth        = EXCLUDED.depth,
          start_ts     = LEAST(pl.start_ts, EXCLUDED.start_ts),
          end_ts       = GREATEST(pl.end_ts, EXCLUDED.end_ts),
          cwd          = EXCLUDED.cwd,
          comm         = EXCLUDED.comm,
          args         = EXCLUDED.args
      RETURNING 1
  )
  SELECT count(*) INTO v_rows FROM ins;

  -- Extend end_ts by HTTP activity in window (response and request)
  WITH http_union AS (
      SELECT host, pid, max(timestamp) AS last_ts
      FROM (
          SELECT host, pid, timestamp FROM http_request WHERE host = p_host AND timestamp BETWEEN p_since AND p_until
          UNION ALL
          SELECT host, pid, timestamp FROM http_response WHERE host = p_host AND timestamp BETWEEN p_since AND p_until
      ) t
      GROUP BY host, pid
  )
  UPDATE process_lifecycle pl
  SET end_ts = GREATEST(pl.end_ts, hu.last_ts)
  FROM http_union hu
  WHERE pl.host = hu.host AND pl.pid = hu.pid;

  RETURN v_rows;
END;
$$;

-- HTTP activity with lifecycle mapping and host propagation
CREATE OR REPLACE VIEW process_http_events AS
WITH http_union AS (
    SELECT
        r.host,
        r.id AS http_id,
        'response' AS http_type,
        r.timestamp,
        r.pid,
        r.tid,
        r.status_code,
        NULL::varchar AS method,
        NULL::varchar AS url,
        r.protocol,
        r.headers,
        r.body,
        r.truncated
    FROM http_response r
    UNION ALL
    SELECT
        q.host,
        q.id AS http_id,
        'request' AS http_type,
        q.timestamp,
        q.pid,
        q.tid,
        NULL::smallint AS status_code,
        q.method,
        q.url,
        q.protocol,
        q.headers,
        q.body,
        q.truncated
    FROM http_request q
),
hdr AS (
    SELECT
      h.*,
      ((h.headers ? 'Mcp-Session-Id') AND coalesce(h.headers->>'Mcp-Session-Id','') <> '')       AS has_mcp_session,
      ((h.headers ? 'Mcp-Protocol-Version') AND coalesce(h.headers->>'Mcp-Protocol-Version','') <> '') AS has_mcp_proto,
      coalesce(h.headers->>'Access-Control-Allow-Headers',  '') AS ac_allow_headers,
      coalesce(h.headers->>'Access-Control-Expose-Headers', '') AS ac_expose_headers
    FROM http_union h
)
SELECT
    h.host,
    h.http_id,
    h.http_type,
    h.timestamp,
    h.pid,
    h.tid,
    h.method,
    h.url,
    h.status_code,
    h.protocol,
    h.headers,
    h.body,
    h.truncated,
    l.exec_id,
    l.root_exec_id,
    l.root_pid,
    l.depth,
    CASE
      WHEN h.http_type = 'request' THEN (
        coalesce(h.url, '') = '/mcp' OR h.has_mcp_proto OR h.has_mcp_session
      )
      WHEN h.http_type = 'response' THEN (
        (POSITION('mcp-session-id' IN h.ac_allow_headers) > 0 AND POSITION('mcp-protocol-version' IN h.ac_allow_headers) > 0)
        OR (POSITION('mcp-session-id' IN h.ac_expose_headers) > 0)
      )
      ELSE FALSE
    END AS is_mcp_http
FROM hdr h
JOIN process_lifecycle l
  ON l.host = h.host AND l.pid = h.pid
 AND h.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout());

-- Response events enriched with lifecycle metadata
CREATE OR REPLACE VIEW response_lineage AS
WITH response_with_context AS (
    SELECT
        r.host,
        r.id AS response_id,
        r.timestamp AS response_ts,
        r.pid,
        r.tid,
        r.status_code,
        r.protocol,
        r.headers AS response_headers,
        r.body AS response_body,
        req.url,
        req.method,
        req.body AS request_body,
        req.headers AS request_headers,
        ROW_NUMBER() OVER (PARTITION BY r.id ORDER BY req.timestamp DESC) AS req_rank
    FROM http_response r
    LEFT JOIN http_request req
      ON req.host = r.host AND req.pid = r.pid AND req.timestamp <= r.timestamp
),
response_enriched AS (
    SELECT
        rc.host,
        rc.response_id,
        rc.response_ts,
        rc.pid,
        rc.tid,
        rc.status_code,
        rc.protocol,
        rc.response_headers,
        rc.response_body,
        rc.url,
        rc.method,
        rc.request_body,
        rc.request_headers
    FROM response_with_context rc
    WHERE rc.req_rank = 1 OR rc.req_rank IS NULL
)
SELECT
    re.host,
    re.response_id,
    re.response_ts,
    re.pid,
    re.tid,
    re.status_code,
    re.protocol,
    re.response_headers,
    re.response_body,
    re.url,
    re.method,
    re.request_body,
    re.request_headers,
    pl.exec_id,
    pl.root_exec_id,
    pl.root_pid,
    pl.depth
FROM response_enriched re
JOIN process_lifecycle pl
  ON pl.host = re.host AND pl.pid = re.pid
 AND re.response_ts BETWEEN pl.start_ts AND (pl.end_ts + analyze_idle_timeout());

-- Correlation summary table and incremental upsert
CREATE TABLE IF NOT EXISTS correlation_summary (
    host                  varchar NOT NULL,
    response_id           uuid    NOT NULL,
    response_ts           timestamptz,
    status_code           integer,
    method                varchar,
    url                   varchar,
    root_exec_id          varchar,
    root_pid              bigint,
    best_event_id         uuid,
    best_event_exec_id    varchar,
    event_root_exec_id    varchar,
    event_root_pid        bigint,
    best_event_comm       varchar,
    best_event_args       varchar,
    best_total_score      numeric,
    best_correlation_type varchar,
    best_gap_ms           double precision,
    best_lineage_score    double precision,
    best_temporal_score   double precision,
    best_argument_score   double precision,
    best_argument_match_flag integer,
    system_actions        jsonb,
    evidence              jsonb,
    PRIMARY KEY (host, response_id)
);
CREATE INDEX IF NOT EXISTS idx_cs_host_ts ON correlation_summary(host, response_ts DESC);
CREATE INDEX IF NOT EXISTS idx_cs_host_score ON correlation_summary(host, best_total_score DESC);
CREATE INDEX IF NOT EXISTS idx_cs_host_status ON correlation_summary(host, status_code);

CREATE OR REPLACE FUNCTION upsert_correlation_summary_incremental(
    p_host  varchar,
    p_since timestamptz,
    p_until timestamptz DEFAULT now()
) RETURNS integer LANGUAGE sql AS $$
WITH exec_lineage AS (
    SELECT
        e.host,
        e.id AS event_id,
    e.timestamp AS event_ts,
        e.pid,
        e.comm,
        e.args,
        pl.exec_id,
        pl.root_exec_id,
        pl.root_pid,
        pl.depth
    FROM exec_events e
    JOIN process_lifecycle pl ON pl.host = e.host AND pl.exec_id = e.exec_id
    WHERE e.host = p_host
),
argument_material AS (
    SELECT
        rl.host,
        rl.response_id,
        lower(
            btrim(
                regexp_replace(
                    COALESCE(rl.response_body::text, '') || ' ' ||
                    COALESCE(rl.request_body::text, '') || ' ' ||
                    COALESCE(rl.url, ''),
                    '\\s+', ' ', 'g'
                )
            )
        ) AS response_text
    FROM response_lineage rl
    WHERE rl.host = p_host
      AND rl.response_ts > p_since AND rl.response_ts <= p_until
),
response_references AS (
    SELECT
        rl.host,
        rl.response_id,
        (
            SELECT array_agg(m[1])
            FROM regexp_matches(lower(COALESCE(rl.response_body::text,'')),
                  '((?:~|/)[a-z0-9._\-]+(?:/[a-z0-9._\-]+)*)', 'g') AS m
        ) AS path_refs,
        (
            SELECT array_agg(m[1])
            FROM regexp_matches(lower(COALESCE(rl.response_body::text,'')),
                  '(https?://[a-z0-9\-._~:/?#@!$&''()*+,;=%]+)', 'g') AS m
        ) AS url_refs,
        (
            SELECT array_agg(m[1])
            FROM regexp_matches(lower(COALESCE(rl.response_body::text,'')),
                  '\\m(cat|ls|grep|find|vim|nano|code|python|node|npm|git|make|gcc|clang)\\M', 'g') AS m
        ) AS command_refs
    FROM response_lineage rl
    WHERE rl.host = p_host
      AND rl.response_ts > p_since AND rl.response_ts <= p_until
),
flattened_references AS (
    SELECT DISTINCT host, response_id, reference
    FROM (
        SELECT host, response_id, unnest(coalesce(path_refs,    ARRAY[]::text[])) AS reference FROM response_references
        UNION ALL
        SELECT host, response_id, unnest(coalesce(url_refs,     ARRAY[]::text[])) AS reference FROM response_references
        UNION ALL
        SELECT host, response_id, unnest(coalesce(command_refs, ARRAY[]::text[])) AS reference FROM response_references
    ) t
    WHERE coalesce(btrim(reference), '') <> ''
),
temporal_candidates AS (
    SELECT
        rl.host,
        rl.response_id,
        rl.response_ts,
        rl.status_code,
        rl.url,
        rl.method,
        rl.root_exec_id AS response_root_exec_id,
        rl.root_pid AS response_root_pid,
        el.event_id,
        el.event_ts,
        el.exec_id AS event_exec_id,
        el.root_exec_id AS event_root_exec_id,
        el.root_pid AS event_root_pid,
        el.comm,
        el.args
    FROM response_lineage rl
    JOIN exec_lineage el
      ON el.host = rl.host
     AND el.event_ts BETWEEN rl.response_ts AND rl.response_ts + INTERVAL '500 milliseconds'
),
lineage_candidates AS (
    SELECT DISTINCT
        rl.host,
        rl.response_id,
        rl.response_ts,
        rl.status_code,
        rl.url,
        rl.method,
        rl.root_exec_id AS response_root_exec_id,
        rl.root_pid AS response_root_pid,
        el.event_id,
        el.event_ts,
        el.exec_id AS event_exec_id,
        el.root_exec_id AS event_root_exec_id,
        el.root_pid AS event_root_pid,
        el.comm,
        el.args
    FROM response_lineage rl
    JOIN exec_lineage el
      ON el.host = rl.host
     AND (
            rl.root_exec_id = el.root_exec_id
         OR (rl.root_pid IS NOT NULL AND el.root_pid IS NOT NULL AND rl.root_pid = el.root_pid)
     )
),
argument_candidates AS (
    SELECT DISTINCT
        rl.host,
        rl.response_id,
        rl.response_ts,
        rl.status_code,
        rl.url,
        rl.method,
        rl.root_exec_id AS response_root_exec_id,
        rl.root_pid AS response_root_pid,
        el.event_id,
        el.event_ts,
        el.exec_id AS event_exec_id,
        el.root_exec_id AS event_root_exec_id,
        el.root_pid AS event_root_pid,
        el.comm,
        el.args
    FROM response_lineage rl
    JOIN flattened_references fr ON fr.host = rl.host AND fr.response_id = rl.response_id
    JOIN exec_lineage el ON el.host = rl.host AND (
            (lower(coalesce(el.args, '')) <> '' AND lower(coalesce(el.args, '')) LIKE '%' || fr.reference || '%')
         OR (lower(coalesce(el.comm, '')) <> '' AND lower(coalesce(el.comm, '')) LIKE '%' || fr.reference || '%')
         OR (fr.reference LIKE '%' || lower(coalesce(el.args, '')) || '%')
         OR (fr.reference LIKE '%' || lower(coalesce(el.comm, '')) || '%')
    )
),
candidate_base AS (
    SELECT DISTINCT
        c.host,
        c.response_id,
        c.response_ts,
        c.status_code,
        c.url,
        c.method,
        c.response_root_exec_id,
        c.response_root_pid,
        c.event_id,
        c.event_ts,
        c.event_exec_id,
        c.event_root_exec_id,
        c.event_root_pid,
        c.comm,
        c.args,
        argument_material.response_text,
        (EXTRACT(EPOCH FROM (c.event_ts - c.response_ts)) * 1000.0) AS gap_ms
    FROM (
        SELECT * FROM temporal_candidates
        UNION ALL
        SELECT * FROM lineage_candidates
        UNION ALL
        SELECT * FROM argument_candidates
    ) c
    LEFT JOIN argument_material ON argument_material.host = c.host AND argument_material.response_id = c.response_id
),
reference_matches AS (
    SELECT
        c.*,
        fr.reference,
        lower(btrim(coalesce(c.args, '') || ' ' || coalesce(c.comm, ''))) AS args_text,
        CASE
            WHEN fr.reference IS NULL OR fr.reference = '' THEN 0.0
            WHEN lower(btrim(coalesce(c.args, '') || ' ' || coalesce(c.comm, ''))) LIKE '%' || fr.reference || '%' THEN 1.0
            WHEN lower(coalesce(c.args, '')) <> '' AND fr.reference LIKE '%' || lower(coalesce(c.args, '')) || '%' THEN 0.5
            WHEN lower(coalesce(c.comm, '')) <> '' AND fr.reference LIKE '%' || lower(coalesce(c.comm, '')) || '%' THEN 0.5
            ELSE 0.0
        END AS per_ref_score
    FROM candidate_base c
    LEFT JOIN flattened_references fr ON fr.host = c.host AND fr.response_id = c.response_id
),
argument_scores AS (
    SELECT
        host,
        response_id,
        event_id,
        COALESCE(AVG(per_ref_score), 0.0) AS argument_score,
        bool_or(per_ref_score >= 0.3) AS argument_match
    FROM reference_matches
    GROUP BY host, response_id, event_id
),
scored AS (
    SELECT
        c.*,
        CASE
            WHEN c.response_root_exec_id = c.event_root_exec_id THEN 1.0
            WHEN c.response_root_pid = c.event_root_pid THEN 0.6
            ELSE 0.0
        END AS lineage_score,
        CASE
            WHEN c.gap_ms >= 0 AND c.gap_ms <= 500 THEN 1 - c.gap_ms / 500.0
            ELSE 0.0
        END AS temporal_score,
        ascore.argument_score,
        COALESCE(ascore.argument_match, FALSE) AS argument_match
    FROM candidate_base c
    LEFT JOIN argument_scores ascore
      ON ascore.host = c.host
     AND ascore.response_id = c.response_id
     AND ascore.event_id = c.event_id
),
ranked AS (
    SELECT
        s.host,
        s.response_id,
        s.event_id,
        s.response_root_exec_id AS root_exec_id,
        s.response_root_pid AS root_pid,
        s.event_exec_id,
        s.event_root_exec_id,
        s.event_root_pid,
        s.gap_ms,
        s.lineage_score,
        s.temporal_score,
        s.argument_score,
        ROUND((0.35 * s.lineage_score + 0.25 * s.temporal_score + 0.40 * s.argument_score)::numeric, 4) AS total_score,
        CASE
            WHEN s.argument_score >= s.lineage_score AND s.argument_score >= s.temporal_score AND s.argument_score > 0 THEN 'argument'
            WHEN s.lineage_score >= s.temporal_score AND s.lineage_score > 0 THEN 'lineage'
            WHEN s.temporal_score > 0 THEN 'temporal'
            ELSE 'none'
        END AS correlation_type,
        s.status_code,
        s.url,
        s.method,
        s.comm AS event_comm,
        s.args AS event_args,
        CASE WHEN s.argument_match THEN 1 ELSE 0 END AS argument_match_flag,
        ROW_NUMBER() OVER (PARTITION BY s.host, s.response_id ORDER BY  
            (0.35 * s.lineage_score + 0.25 * s.temporal_score + 0.40 * s.argument_score) DESC,
            s.temporal_score DESC, s.lineage_score DESC, s.gap_ms ASC
        ) AS rn
    FROM scored s
),
best_events AS (
    SELECT * FROM ranked WHERE rn = 1
),
action_lists AS (
    SELECT
        host,
        response_id,
        jsonb_agg(
            jsonb_build_object(
                'event_id', event_id,
                'event_exec_id', event_exec_id,
                'event_root_exec_id', event_root_exec_id,
                'event_root_pid', event_root_pid,
                'comm', event_comm,
                'args', event_args,
                'correlation_type', correlation_type,
                'gap_ms', gap_ms,
                'lineage_score', lineage_score,
                'temporal_score', temporal_score,
                'argument_score', argument_score,
                'total_score', total_score,
                'argument_match', argument_match_flag
            )
            ORDER BY total_score DESC, gap_ms ASC
        ) AS action_structs
    FROM ranked
    GROUP BY host, response_id
),
response_refs AS (
    WITH material AS (
        SELECT
            rl.host,
            rl.response_id,
            lower(COALESCE(rl.response_body::text, '')) AS response_body,
            lower(COALESCE(rl.request_body::text, '')) AS request_body,
            lower(COALESCE(rl.url, '')) AS url_text
        FROM response_lineage rl
        WHERE rl.host = p_host
          AND rl.response_ts > p_since AND rl.response_ts <= p_until
    )
    SELECT
        host,
        response_id,
        array_agg(ref ORDER BY ref) AS references_list
    FROM (
        SELECT host, response_id, unnest(coalesce( (SELECT array_agg(m[1]) FROM regexp_matches(response_body,'((?:~|/)[a-z0-9._\-]+(?:/[a-z0-9._\-]+)*)','g') m ), ARRAY[]::text[])) AS ref FROM material
        UNION ALL
        SELECT host, response_id, unnest(coalesce( (SELECT array_agg(m[1]) FROM regexp_matches(response_body,'(https?://[a-z0-9\-._~:/?#@!$&''()*+,;=%]+)','g') m ), ARRAY[]::text[])) AS ref FROM material
        UNION ALL
        SELECT host, response_id, unnest(coalesce( (SELECT array_agg(m[1]) FROM regexp_matches(response_body,'\m(cat|ls|grep|find|vim|nano|code|python|node|npm|git|make|gcc|clang)\M','g') m ), ARRAY[]::text[])) AS ref FROM material
        UNION ALL
        SELECT host, response_id, unnest(coalesce( (SELECT array_agg(m[1]) FROM regexp_matches(request_body,'((?:~|/)[a-z0-9._\-]+(?:/[a-z0-9._\-]+)*)','g') m ), ARRAY[]::text[])) AS ref FROM material
        UNION ALL
        SELECT host, response_id, unnest(coalesce( (SELECT array_agg(m[1]) FROM regexp_matches(url_text,'(https?://[a-z0-9\-._~:/?#@!$&''()*+,;=%]+)','g') m ), ARRAY[]::text[])) AS ref FROM material
    ) refs
    WHERE coalesce(btrim(ref), '') <> ''
    GROUP BY host, response_id
),
response_info AS (
    SELECT
        rl.host,
        rl.response_id,
        rl.response_ts,
        rl.status_code,
        rl.method,
        rl.url,
        rl.root_exec_id,
        rl.root_pid
    FROM response_lineage rl
    WHERE rl.host = p_host
      AND rl.response_ts > p_since AND rl.response_ts <= p_until
),
final AS (
    SELECT
        be.host,
        be.response_id,
        ri.response_ts,
        ri.status_code,
        ri.method,
        ri.url,
        ri.root_exec_id,
        ri.root_pid,
        be.event_id AS best_event_id,
        be.event_exec_id AS best_event_exec_id,
        be.event_root_exec_id,
        be.event_root_pid,
        be.event_comm AS best_event_comm,
        be.event_args AS best_event_args,
        be.total_score AS best_total_score,
        be.correlation_type AS best_correlation_type,
        be.gap_ms AS best_gap_ms,
        be.lineage_score AS best_lineage_score,
        be.temporal_score AS best_temporal_score,
        be.argument_score AS best_argument_score,
        be.argument_match_flag AS best_argument_match_flag,
        COALESCE(al.action_structs, '[]'::jsonb) AS system_actions,
        jsonb_build_object(
            'llm_references', COALESCE(to_jsonb(rr.references_list), '[]'::jsonb),
            'time_window_ms', 500,
            'top_event', jsonb_build_object(
                'event_id', be.event_id,
                'total_score', be.total_score,
                'lineage_score', be.lineage_score,
                'temporal_score', be.temporal_score,
                'argument_score', be.argument_score,
                'gap_ms', be.gap_ms,
                'argument_match', be.argument_match_flag
            )
        ) AS evidence
    FROM best_events be
    LEFT JOIN action_lists al ON al.host = be.host AND al.response_id = be.response_id
    LEFT JOIN response_refs rr ON rr.host = be.host AND rr.response_id = be.response_id
    LEFT JOIN response_info ri ON ri.host = be.host AND ri.response_id = be.response_id
)
, ins AS (
INSERT INTO correlation_summary AS cs (
    host, response_id, response_ts, status_code, method, url,
    root_exec_id, root_pid,
    best_event_id, best_event_exec_id, event_root_exec_id, event_root_pid,
    best_event_comm, best_event_args,
    best_total_score, best_correlation_type, best_gap_ms,
    best_lineage_score, best_temporal_score, best_argument_score, best_argument_match_flag,
    system_actions, evidence
)
SELECT * FROM final
ON CONFLICT (host, response_id) DO UPDATE SET
    response_ts           = EXCLUDED.response_ts,
    status_code           = EXCLUDED.status_code,
    method                = EXCLUDED.method,
    url                   = EXCLUDED.url,
    root_exec_id          = EXCLUDED.root_exec_id,
    root_pid              = EXCLUDED.root_pid,
    best_event_id         = EXCLUDED.best_event_id,
    best_event_exec_id    = EXCLUDED.best_event_exec_id,
    event_root_exec_id    = EXCLUDED.event_root_exec_id,
    event_root_pid        = EXCLUDED.event_root_pid,
    best_event_comm       = EXCLUDED.best_event_comm,
    best_event_args       = EXCLUDED.best_event_args,
    best_total_score      = EXCLUDED.best_total_score,
    best_correlation_type = EXCLUDED.best_correlation_type,
    best_gap_ms           = EXCLUDED.best_gap_ms,
    best_lineage_score    = EXCLUDED.best_lineage_score,
    best_temporal_score   = EXCLUDED.best_temporal_score,
    best_argument_score   = EXCLUDED.best_argument_score,
    best_argument_match_flag = EXCLUDED.best_argument_match_flag,
    system_actions        = EXCLUDED.system_actions,
    evidence              = EXCLUDED.evidence
RETURNING 1)
SELECT count(*) FROM ins;
$$;

-- Watermark and orchestrator for micro-batch tick
CREATE TABLE IF NOT EXISTS analysis_watermark (
    host varchar PRIMARY KEY,
    last_response_ts timestamptz
);

CREATE OR REPLACE FUNCTION run_analyze_tick(
    p_host  varchar,
    p_since timestamptz,
    p_until timestamptz DEFAULT now()
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  PERFORM refresh_process_lifecycle_incremental(p_host, p_since, p_until);
  PERFORM upsert_correlation_summary_incremental(p_host, p_since, p_until);
END;
$$;

-- Fully automated micro-batch tick based on watermark
CREATE OR REPLACE FUNCTION run_analyze_tick_from_watermark(
    p_host    varchar,
    p_horizon interval DEFAULT interval '60 seconds',
    p_lag     interval DEFAULT interval '1 second'
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  v_now   timestamptz := now();
  v_last  timestamptz;
  v_since timestamptz;
  v_until timestamptz := v_now - p_lag;
BEGIN
  -- Ensure watermark row exists
  INSERT INTO analysis_watermark(host, last_response_ts)
  VALUES (p_host, v_now - p_horizon)
  ON CONFLICT (host) DO NOTHING;

  SELECT last_response_ts INTO v_last
  FROM analysis_watermark
  WHERE host = p_host;

  v_since := COALESCE(v_last, v_now - p_horizon);

  IF v_until <= v_since THEN
    RETURN; -- nothing to do
  END IF;

  PERFORM refresh_process_lifecycle_incremental(p_host, v_since, v_until);
  PERFORM upsert_correlation_summary_incremental(p_host, v_since, v_until);

  UPDATE analysis_watermark
  SET last_response_ts = v_until
  WHERE host = p_host;
END;
$$;

-- Heuristic alerts with host scoping
CREATE TABLE IF NOT EXISTS heuristic_alerts (
    alert_id    TEXT PRIMARY KEY,
    alert_type  TEXT NOT NULL,
    host        TEXT NOT NULL,
    root_exec_id TEXT,
    root_pid    BIGINT,
    severity    TEXT,
    score       DOUBLE PRECISION,
    start_ts    TIMESTAMPTZ NOT NULL,
    end_ts      TIMESTAMPTZ,
    details     JSONB
);

WITH response_nodes AS (
    SELECT
        rl.host,
        rl.response_id,
        rl.response_ts,
        rl.status_code,
        rl.root_exec_id,
        rl.root_pid,
        regexp_replace(lower(COALESCE(rl.response_body::text, '')), '\\s+', ' ', 'g') AS normalized_body
    FROM response_lineage rl
),
reasoning_loops AS (
    SELECT
        concat('reasoning_loop:', host, ':', root_exec_id, ':', status_code, ':', normalized_body) AS alert_id,
        'reasoning_loop' AS alert_type,
        host,
        root_exec_id,
        root_pid,
        'medium' AS severity,
        COUNT(*)::double precision AS score,
        min(response_ts) AS start_ts,
        max(response_ts) AS end_ts,
        jsonb_build_object('status_code', status_code, 'response_body', normalized_body, 'occurrences', COUNT(*)) AS details
    FROM response_nodes
    WHERE normalized_body <> ''
    GROUP BY host, root_exec_id, root_pid, status_code, normalized_body
    HAVING COUNT(*) >= 2
),
sensitive_reads AS (
    SELECT
        e.host,
        e.id AS event_id,
    e.timestamp AS timestamp,
        pl.root_exec_id,
        pl.root_pid,
        pl.exec_id,
        lower(COALESCE(e.args, '')) AS args,
        lower(COALESCE(e.comm, '')) AS comm
    FROM exec_events e
    JOIN process_lifecycle pl ON pl.host = e.host AND pl.exec_id = e.exec_id
     WHERE e.args ~* '(/etc/passwd|/etc/shadow|\\.ssh)'
        OR e.comm ~* 'scp|sftp|curl'
),
http_requests AS (
    SELECT
        q.host,
        q.id AS request_id,
        q.timestamp,
        q.pid,
        q.url,
        q.method,
        q.headers,
        q.body,
        pl.root_exec_id,
        pl.root_pid
    FROM http_request q
    JOIN process_lifecycle pl
      ON pl.host = q.host AND pl.pid = q.pid
     AND q.timestamp BETWEEN pl.start_ts AND (pl.end_ts + analyze_idle_timeout())
),
exfiltration AS (
    SELECT
        concat('data_exfiltration:', sr.host, ':', sr.root_exec_id, ':', sr.exec_id, ':', hr.request_id) AS alert_id,
        'data_exfiltration' AS alert_type,
        sr.host,
        sr.root_exec_id,
        sr.root_pid,
        'high' AS severity,
        GREATEST(0.0, 1 - (EXTRACT(EPOCH FROM (hr.timestamp - sr.timestamp)) * 1000.0) / 5000.0) AS score,
        sr.timestamp AS start_ts,
        hr.timestamp AS end_ts,
        jsonb_build_object(
            'sensitive_args', sr.args,
            'command', sr.comm,
            'url', hr.url,
            'method', hr.method,
            'request_headers', hr.headers::text
        ) AS details
    FROM sensitive_reads sr
    JOIN http_requests hr
      ON hr.host = sr.host AND hr.root_exec_id = sr.root_exec_id
     AND hr.timestamp BETWEEN sr.timestamp AND sr.timestamp + INTERVAL '5 seconds'
)
INSERT INTO heuristic_alerts (
    alert_id,
    alert_type,
    host,
    root_exec_id,
    root_pid,
    severity,
    score,
    start_ts,
    end_ts,
    details
)
SELECT * FROM reasoning_loops
UNION ALL
SELECT * FROM exfiltration
ON CONFLICT (alert_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS security_analysis_results (
    id UUID DEFAULT uuidv7(),
    analyzed_at TIMESTAMPTZ DEFAULT now(),
    host VARCHAR,
    root_exec_id VARCHAR,
    threat_level INTEGER,
    threat_type VARCHAR,
    confidence DOUBLE PRECISION,
    summary VARCHAR,
    details VARCHAR,
    recommendations JSONB,
    evidence JSONB,
    raw_json JSONB
);
CREATE TABLE IF NOT EXISTS llm_prompt_injection_results (
    request_id UUID,
    host VARCHAR,
    severity_level VARCHAR,
    categories VARCHAR
);

