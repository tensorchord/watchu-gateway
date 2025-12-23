-- Data source observability queries (S3 + Postgres).

-- name: GetDataSourceDistributionByHostRange :many
SELECT
    's3'::text AS source,
    COUNT(*)::bigint AS hits
FROM process_s3_events s3
WHERE s3.host = sqlc.arg('host')
  AND s3.timestamp >= sqlc.arg('since')
  AND s3.timestamp <= sqlc.arg('until')
  AND (sqlc.narg('root_exec_id')::text IS NULL OR s3.root_exec_id = sqlc.narg('root_exec_id')::text)
UNION ALL
SELECT
    'postgres'::text AS source,
    COUNT(*)::bigint AS hits
FROM pg_event e
LEFT JOIN process_lifecycle l
  ON l.host = e.host
 AND l.pid = e.pid
 AND e.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
WHERE e.host = sqlc.arg('host')
  AND e.timestamp >= sqlc.arg('since')
  AND e.timestamp <= sqlc.arg('until')
  AND (sqlc.narg('root_exec_id')::text IS NULL OR l.root_exec_id = sqlc.narg('root_exec_id')::text);

-- name: ListDataSourceDistributionByRootExecIDRange :many
WITH s3 AS (
    SELECT
        s3.root_exec_id,
        MAX(s3.root_pid)::bigint AS root_pid,
        COUNT(*)::bigint AS hits
    FROM process_s3_events s3
    WHERE s3.host = sqlc.arg('host')
      AND s3.timestamp >= sqlc.arg('since')
      AND s3.timestamp <= sqlc.arg('until')
      AND s3.root_exec_id IS NOT NULL
    GROUP BY s3.root_exec_id
),
pg AS (
    SELECT
        l.root_exec_id,
        MAX(l.root_pid)::bigint AS root_pid,
        COUNT(*)::bigint AS hits
    FROM pg_event e
    INNER JOIN process_lifecycle l
      ON l.host = e.host
     AND l.pid = e.pid
     AND e.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
    WHERE e.host = sqlc.arg('host')
      AND e.timestamp >= sqlc.arg('since')
      AND e.timestamp <= sqlc.arg('until')
      AND l.root_exec_id IS NOT NULL
    GROUP BY l.root_exec_id
)
SELECT root_exec_id, root_pid, 's3'::text AS source, hits FROM s3
UNION ALL
SELECT root_exec_id, root_pid, 'postgres'::text AS source, hits FROM pg
ORDER BY hits DESC
LIMIT sqlc.arg('limit');

-- name: ListS3BucketsTopNByHostRange :many
WITH enriched AS (
    SELECT
        COALESCE(
            NULLIF(bucket, ''),
            FIRST_VALUE(NULLIF(bucket, '')) OVER (
                PARTITION BY root_exec_id, pid
                ORDER BY CASE WHEN bucket IS NOT NULL AND bucket <> '' THEN 0 ELSE 1 END, timestamp
                ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
            )
        ) AS inferred_bucket
    FROM process_s3_events
    WHERE process_s3_events.host = sqlc.arg('host')
      AND process_s3_events.timestamp >= sqlc.arg('since')
      AND process_s3_events.timestamp <= sqlc.arg('until')
      AND (sqlc.narg('root_exec_id')::text IS NULL OR process_s3_events.root_exec_id = sqlc.narg('root_exec_id')::text)
)
SELECT
    COALESCE(NULLIF(inferred_bucket, ''), '(unknown)') AS bucket,
    COUNT(*)::bigint AS hits
FROM enriched
GROUP BY COALESCE(NULLIF(inferred_bucket, ''), '(unknown)')
ORDER BY hits DESC, bucket ASC
LIMIT sqlc.arg('limit');

-- name: ListS3StatusCountsByHostRange :many
SELECT
    status_code,
    COUNT(*)::bigint AS hits
FROM process_s3_events
WHERE process_s3_events.host = sqlc.arg('host')
  AND process_s3_events.timestamp >= sqlc.arg('since')
  AND process_s3_events.timestamp <= sqlc.arg('until')
  AND (sqlc.narg('root_exec_id')::text IS NULL OR process_s3_events.root_exec_id = sqlc.narg('root_exec_id')::text)
GROUP BY process_s3_events.status_code
ORDER BY hits DESC, status_code ASC
LIMIT sqlc.arg('limit');

-- name: ListS3OperationCountsByHostRange :many
SELECT
    operation,
    COUNT(*)::bigint AS hits
FROM process_s3_events
WHERE process_s3_events.host = sqlc.arg('host')
  AND process_s3_events.timestamp >= sqlc.arg('since')
  AND process_s3_events.timestamp <= sqlc.arg('until')
  AND (sqlc.narg('root_exec_id')::text IS NULL OR process_s3_events.root_exec_id = sqlc.narg('root_exec_id')::text)
  AND process_s3_events.operation IS NOT NULL
GROUP BY process_s3_events.operation
ORDER BY hits DESC, operation ASC
LIMIT sqlc.arg('limit');

-- name: ListProcessS3EventsByHostRange :many
WITH enriched_events AS (
    SELECT
        host,
        response_id,
        request_id,
        timestamp,
        pid,
        tid,
        comm,
        method,
        url,
        status_code,
        bucket,
        bucket_region,
        object_key,
        request_bytes,
        response_bytes,
        container_id,
        exec_id,
        root_exec_id,
        root_pid,
        depth,
        operation,
        -- Use window function to infer bucket from the same session (same root_exec_id and pid)
        COALESCE(
            NULLIF(bucket, ''),
            FIRST_VALUE(NULLIF(bucket, '')) OVER (
                PARTITION BY root_exec_id, pid 
                ORDER BY CASE WHEN bucket IS NOT NULL AND bucket <> '' THEN 0 ELSE 1 END, timestamp
                ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
            )
        ) AS inferred_bucket,
        -- Use window function to infer region from the same session
        COALESCE(
            NULLIF(bucket_region, ''),
            FIRST_VALUE(NULLIF(bucket_region, '')) OVER (
                PARTITION BY root_exec_id, pid 
                ORDER BY CASE WHEN bucket_region IS NOT NULL AND bucket_region <> '' THEN 0 ELSE 1 END, timestamp
                ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
            )
        ) AS inferred_region
    FROM process_s3_events
    WHERE host = sqlc.arg('host')
      AND timestamp >= sqlc.arg('since')
      AND timestamp <= sqlc.arg('until')
      AND (sqlc.narg('root_exec_id')::text IS NULL OR root_exec_id = sqlc.narg('root_exec_id')::text)
      AND (sqlc.narg('operation')::text IS NULL OR operation = sqlc.narg('operation')::text)
)
SELECT
    host,
    response_id,
    request_id,
    timestamp,
    pid,
    tid,
    comm,
    method,
    url,
    status_code,
    COALESCE(NULLIF(inferred_bucket, ''), '(unknown)') AS bucket,
    inferred_region AS bucket_region,
    object_key,
    request_bytes,
    response_bytes,
    container_id,
    exec_id,
    root_exec_id,
    root_pid,
    depth,
    operation
FROM enriched_events
WHERE (
    sqlc.narg('bucket')::text IS NULL
    OR (sqlc.narg('bucket')::text = '(unknown)' AND (inferred_bucket IS NULL OR inferred_bucket = ''))
    OR inferred_bucket = sqlc.narg('bucket')::text
)
ORDER BY timestamp DESC
LIMIT sqlc.arg('limit');

-- name: ListPostgresQueriesTopNByHostRange :many
WITH decoded AS (
    SELECT
        e.host,
        e.timestamp,
        l.root_exec_id,
        CASE
            WHEN e.msg_type = 'Q' AND e.data IS NOT NULL THEN safe_text_from_bytea(strip_cstring_terminator(e.data))::text
            ELSE NULL::text
        END AS sql_text
    FROM pg_event e
    LEFT JOIN process_lifecycle l
      ON l.host = e.host
     AND l.pid = e.pid
     AND e.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
    WHERE e.host = sqlc.arg('host')
      AND e.timestamp >= sqlc.arg('since')
      AND e.timestamp <= sqlc.arg('until')
      AND e.msg_type = 'Q'
      AND (sqlc.narg('root_exec_id')::text IS NULL OR l.root_exec_id = sqlc.narg('root_exec_id')::text)
),
hashed AS (
    SELECT
        sql_text,
        CASE
            WHEN sql_text IS NULL THEN NULL::text
            ELSE md5(lower(regexp_replace(sql_text, '\\s+', ' ', 'g')))::text
        END AS sql_hash
    FROM decoded
)
SELECT
    sql_hash::text AS sql_hash,
    MIN(sql_text)::text AS sample,
    COUNT(*)::bigint AS hits
FROM hashed
WHERE sql_hash IS NOT NULL
GROUP BY sql_hash
ORDER BY hits DESC, sql_hash ASC
LIMIT sqlc.arg('limit');

-- name: ListProcessPGEventsByHostRange :many
SELECT
    host,
    pg_event_id,
    timestamp,
    pid,
    tid,
    uid,
    gid,
    comm,
    msg_type,
    container_id,
    exec_id,
    root_exec_id,
    root_pid,
    depth,
    base.sql_text::text AS sql_text,
    hash.sql_hash::text AS sql_hash
FROM (
    SELECT
        e.host,
        e.id AS pg_event_id,
        e.timestamp,
        e.pid,
        e.tid,
        e.uid,
        e.gid,
        e.comm,
        e.msg_type,
        e.container_id,
        l.exec_id,
        l.root_exec_id,
        l.root_pid,
        l.depth,
        COALESCE(
            CASE
                WHEN e.msg_type = 'Q' AND e.data IS NOT NULL THEN safe_text_from_bytea(strip_cstring_terminator(e.data))::text
                ELSE NULL::text
            END,
            ''::text
        ) AS sql_text
    FROM pg_event e
    LEFT JOIN process_lifecycle l
      ON l.host = e.host
     AND l.pid = e.pid
     AND e.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
    WHERE e.host = sqlc.arg('host')
      AND e.timestamp >= sqlc.arg('since')
      AND e.timestamp <= sqlc.arg('until')
) base
LEFT JOIN LATERAL (
    SELECT COALESCE(
        CASE
            WHEN base.sql_text = '' THEN NULL::text
            ELSE md5(lower(regexp_replace(base.sql_text, '\\s+', ' ', 'g')))::text
        END,
        ''::text
    )::text AS sql_hash
) hash ON TRUE
WHERE (sqlc.narg('root_exec_id')::text IS NULL OR base.root_exec_id = sqlc.narg('root_exec_id')::text)
  AND (sqlc.narg('msg_type')::text IS NULL OR base.msg_type = sqlc.narg('msg_type')::text)
  AND (sqlc.narg('sql_hash')::text IS NULL OR hash.sql_hash = sqlc.narg('sql_hash')::text)
ORDER BY base.timestamp DESC
LIMIT sqlc.arg('limit');
