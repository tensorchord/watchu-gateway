package analysis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PromptEvaluator interface {
	Enabled() bool
	Run(ctx context.Context, host string, since, until time.Time) error
}

// Scheduler periodically drives incremental analysis in the database.
type Scheduler struct {
	pool       *pgxpool.Pool
	interval   time.Duration
	lookback   time.Duration
	horizon    time.Duration
	lag        time.Duration
	maxWindow  time.Duration
	logger     *slog.Logger
	now        func() time.Time
	promptEval PromptEvaluator
}

// NewScheduler wires scheduler configuration with dependencies.
func NewScheduler(pool *pgxpool.Pool, interval, lookback, horizon, lag, maxWindow time.Duration, promptEval PromptEvaluator, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		pool:       pool,
		interval:   interval,
		lookback:   lookback,
		horizon:    horizon,
		lag:        lag,
		maxWindow:  maxWindow,
		logger:     logger,
		now:        time.Now,
		promptEval: promptEval,
	}
}

// Run starts the scheduler loop until the context is canceled.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context) {
	since := s.now().Add(-s.lookback)
	hosts, err := s.fetchActiveHosts(ctx, since)
	if err != nil {
		s.logger.Error("fetch active hosts failed", slog.String("error", err.Error()))
		return
	}

	if len(hosts) == 0 {
		return
	}

	for _, host := range hosts {
		if err := s.runAnalysis(ctx, host); err != nil {
			s.logger.Error("analysis tick failed", slog.String("host", host), slog.String("error", err.Error()))
		}
	}
}

func (s *Scheduler) fetchActiveHosts(ctx context.Context, since time.Time) ([]string, error) {
	tables := []string{"http_response", "http_request", "exec_events"}
	hostSet := make(map[string]struct{})

	for _, table := range tables {
		hosts, err := s.fetchHostsFromTable(ctx, table, since)
		if err != nil {
			return nil, err
		}
		for _, host := range hosts {
			hostSet[host] = struct{}{}
		}
	}

	// If the scheduler was down (or the lookback window is too small), a host may
	// have unprocessed data even though it hasn't sent events recently. Include any
	// hosts whose latest response timestamp is newer than the analysis watermark so
	// we can catch up.
	backlogHosts, err := s.fetchBacklogHosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, host := range backlogHosts {
		hostSet[host] = struct{}{}
	}

	if len(hostSet) == 0 {
		return nil, nil
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (s *Scheduler) fetchBacklogHosts(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT w.host
		FROM analysis_watermark w
		WHERE EXISTS (
			SELECT 1
			FROM http_response r
			WHERE r.host = w.host
			  AND r.timestamp > w.last_response_ts
			LIMIT 1
		)
		UNION
		SELECT DISTINCT r.host
		FROM http_response r
		WHERE NOT EXISTS (
			SELECT 1
			FROM analysis_watermark w
			WHERE w.host = r.host
		)
	`)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			// Optional feature: allow the gateway to run before analysis tables exist.
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return hosts, nil
}

func (s *Scheduler) fetchHostsFromTable(ctx context.Context, table string, since time.Time) ([]string, error) {
	switch table {
	case "http_response", "http_request", "exec_events":
	default:
		return nil, fmt.Errorf("unsupported host source table: %s", table)
	}

	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT DISTINCT host FROM %s WHERE timestamp >= $1`, table), since)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			// Table not yet migrated; treat as empty source.
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return hosts, nil
}

func (s *Scheduler) latestHTTPResponseTimestamp(ctx context.Context, host string) (*time.Time, error) {
	var latest pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `SELECT max(timestamp) FROM http_response WHERE host = $1`, host).Scan(&latest)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return nil, nil
		}
		return nil, err
	}
	if !latest.Valid || latest.Time.IsZero() {
		return nil, nil
	}
	val := latest.Time
	return &val, nil
}

func (s *Scheduler) runAnalysis(ctx context.Context, host string) error {
	until := s.now().Add(-s.lag)
	if until.IsZero() {
		return nil
	}

	// Clamp "until" to the newest response timestamp so we don't advance the analysis
	// watermark past available data (e.g. when ingest timestamps lag wall-clock).
	latestResponseTS, err := s.latestHTTPResponseTimestamp(ctx, host)
	if err != nil {
		return err
	}
	if latestResponseTS == nil {
		return nil
	}
	if latestResponseTS.Before(until) {
		until = *latestResponseTS
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	windowSince, _, err := s.ensureWatermark(ctx, tx, host, until)
	if err != nil {
		return err
	}
	if s.maxWindow > 0 {
		maxUntil := windowSince.Add(s.maxWindow)
		if maxUntil.Before(until) {
			until = maxUntil
		}
	}
	promptSince := windowSince
	promptUntil := until

	if !windowSince.Before(until) {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		s.runPromptInjection(ctx, host, promptSince, promptUntil)
		return nil
	}

	s.logger.Info(
		"analysis window",
		slog.String("host", host),
		slog.Time("since", windowSince),
		slog.Time("until", until),
	)

	if err := s.refreshProcessLifecycle(ctx, tx, host, windowSince, until); err != nil {
		return err
	}

	if err := s.populateProcessHTTP(ctx, tx, host, windowSince, until); err != nil {
		return err
	}
	if err := s.populateProcessS3(ctx, tx, host, windowSince, until); err != nil {
		return err
	}

	if err := s.updateWatermark(ctx, tx, host, until); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Optional enrichment steps run in separate transactions so a failure does not
	// roll back the core derived tables (process_http_events/process_s3_events/etc.)
	// or prevent watermark advancement.
	s.runOptionalEnrichments(ctx, host, windowSince, until)

	s.runPromptInjection(ctx, host, promptSince, promptUntil)
	return nil
}

func (s *Scheduler) runOptionalEnrichments(ctx context.Context, host string, since, until time.Time) {
	steps := []struct {
		name string
		run  func(ctx context.Context, tx pgx.Tx) error
	}{
		{
			name: "populate_process_pg_events",
			run: func(ctx context.Context, tx pgx.Tx) error {
				return s.populateProcessPG(ctx, tx, host, since, until)
			},
		},
		{
			name: "populate_llm_http_events",
			run: func(ctx context.Context, tx pgx.Tx) error {
				return s.populateLLMHTTP(ctx, tx, host, since, until)
			},
		},
		{
			name: "populate_correlation_summary",
			run: func(ctx context.Context, tx pgx.Tx) error {
				return s.populateCorrelationSummary(ctx, tx, host, since, until)
			},
		},
		{
			name: "populate_heuristic_alerts",
			run: func(ctx context.Context, tx pgx.Tx) error {
				return s.populateHeuristicAlerts(ctx, tx, host, since, until)
			},
		},
		{
			name: "upsert_agent_hierarchy",
			run: func(ctx context.Context, tx pgx.Tx) error {
				return s.populateAgentHierarchy(ctx, tx, host, since, until)
			},
		},
	}

	for _, step := range steps {
		if err := s.runOptionalStep(ctx, step.name, step.run); err != nil {
			s.logger.Warn("optional analysis enrichment failed", slog.String("host", host), slog.String("step", step.name), slog.String("error", err.Error()))
		}
	}
}

func (s *Scheduler) runOptionalStep(ctx context.Context, name string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err := fn(ctx, tx); err != nil {
		if isMissingFeatureErr(err) {
			return nil
		}
		return err
	}

	return tx.Commit(ctx)
}

func isMissingFeatureErr(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	// 42P01: undefined_table, 42883: undefined_function
	return pgErr.Code == "42P01" || pgErr.Code == "42883"
}

func (s *Scheduler) runPromptInjection(ctx context.Context, host string, since, until time.Time) {
	if s.promptEval == nil || !s.promptEval.Enabled() {
		return
	}
	if err := s.promptEval.Run(ctx, host, since, until); err != nil {
		s.logger.Warn("prompt injection run failed", slog.String("host", host), slog.String("error", err.Error()))
	}
}

func (s *Scheduler) ensureWatermark(ctx context.Context, tx pgx.Tx, host string, until time.Time) (time.Time, time.Time, error) {
	var last time.Time
	err := tx.QueryRow(ctx, `SELECT last_response_ts FROM analysis_watermark WHERE host = $1`, host).Scan(&last)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Seed watermark slightly behind so the first analysis pass has extra overlap
			// (helps when the scheduler starts after a burst of ingest).
			last = until.Add(-s.horizon)
			_, execErr := tx.Exec(ctx, `INSERT INTO analysis_watermark(host, last_response_ts) VALUES ($1, $2)`, host, last)
			if execErr != nil {
				var pgErr *pgconn.PgError
				if errors.As(execErr, &pgErr) && pgErr.Code == "23505" {
					return s.ensureWatermark(ctx, tx, host, until)
				}
				return time.Time{}, time.Time{}, execErr
			}
		} else {
			return time.Time{}, time.Time{}, err
		}
	}

	since := last.Add(-s.horizon)
	if since.After(until) {
		since = last
	}

	return since, last, nil
}

func (s *Scheduler) populateProcessHTTP(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	// Window rank ensures we only upsert a single row per (host, http_id, http_type).
	_, err := tx.Exec(ctx, `
		WITH http_union AS (
			SELECT
				resp.host,
				resp.id AS http_id,
				'response' AS http_type,
				resp.timestamp,
				resp.pid,
				resp.tid,
				resp.status_code::int,
				NULL::varchar AS method,
				NULL::varchar AS url,
				resp.protocol,
				resp.headers,
				resp.body,
				resp.truncated
			FROM http_response resp
			WHERE resp.host = $1
			  AND resp.timestamp > $2
			  AND resp.timestamp <= $3
			UNION ALL
			SELECT
				req.host,
				req.id AS http_id,
				'request' AS http_type,
				req.timestamp,
				req.pid,
				req.tid,
				NULL::int,
				req.method,
				req.url,
				req.protocol,
				req.headers,
				req.body,
				req.truncated
			FROM http_request req
			WHERE req.host = $1
			  AND req.timestamp > $2
			  AND req.timestamp <= $3
		),
		hdr AS (
			SELECT
				h.*,
				((h.headers ? 'Mcp-Session-Id') AND coalesce(h.headers->>'Mcp-Session-Id','') <> '')       AS has_mcp_session,
				((h.headers ? 'Mcp-Protocol-Version') AND coalesce(h.headers->>'Mcp-Protocol-Version','') <> '') AS has_mcp_proto,
				coalesce(h.headers->>'Access-Control-Allow-Headers',  '') AS ac_allow_headers,
				coalesce(h.headers->>'Access-Control-Expose-Headers', '') AS ac_expose_headers
			FROM http_union h
		),
		ranked AS (
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
				END AS is_mcp_http,
				ROW_NUMBER() OVER (
					PARTITION BY h.host, h.http_id, h.http_type
					ORDER BY l.start_ts DESC, l.depth ASC
				) AS row_num
			FROM hdr h
			JOIN process_lifecycle l
			  ON l.host = h.host AND l.pid = h.pid
			 AND h.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
		),
		enriched AS (
			SELECT
				host,
				http_id,
				http_type,
				timestamp,
				pid,
				tid,
				method,
				url,
				status_code,
				protocol,
				headers,
				body,
				truncated,
				exec_id,
				root_exec_id,
				root_pid,
				depth,
				is_mcp_http
			FROM ranked
			WHERE row_num = 1
		)
		INSERT INTO process_http_events (
			host, http_id, http_type, timestamp, pid, tid, method, url, status_code,
			protocol, headers, body, truncated, exec_id, root_exec_id, root_pid,
			depth, is_mcp_http
		)
		SELECT
			host, http_id, http_type, timestamp, pid, tid, method, url, status_code,
			protocol, headers, body, truncated, exec_id, root_exec_id, root_pid,
			depth, is_mcp_http
		FROM enriched
		ON CONFLICT (host, http_id, http_type) DO UPDATE
		SET timestamp = EXCLUDED.timestamp,
			pid = EXCLUDED.pid,
			tid = EXCLUDED.tid,
			method = EXCLUDED.method,
			url = EXCLUDED.url,
			status_code = EXCLUDED.status_code,
			protocol = EXCLUDED.protocol,
			headers = EXCLUDED.headers,
			body = EXCLUDED.body,
			truncated = EXCLUDED.truncated,
			exec_id = EXCLUDED.exec_id,
			root_exec_id = EXCLUDED.root_exec_id,
			root_pid = EXCLUDED.root_pid,
			depth = EXCLUDED.depth,
			is_mcp_http = EXCLUDED.is_mcp_http;
	`, host, since, until)
	return err
}

func (s *Scheduler) populateProcessPG(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	_, err := tx.Exec(ctx, `
			WITH source_events AS (
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
				e.data,
				e.container_id,
				l.exec_id,
				l.root_exec_id,
				l.root_pid,
				l.depth,
					CASE
						WHEN e.msg_type = 'Q' AND e.data IS NOT NULL THEN safe_text_from_bytea(strip_cstring_terminator(e.data))
						ELSE NULL
					END AS sql_text
				FROM pg_event e
				LEFT JOIN LATERAL (
					SELECT
						l.exec_id,
						l.root_exec_id,
						l.root_pid,
						l.depth
					FROM process_lifecycle l
					WHERE l.host = e.host
					  AND l.pid = e.pid
					  AND e.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
					ORDER BY l.start_ts DESC, l.depth ASC
					LIMIT 1
				) l ON TRUE
				WHERE e.host = $1 AND e.timestamp > $2 AND e.timestamp <= $3
			),
			enriched AS (
				SELECT
				*,
				CASE
					WHEN sql_text IS NULL THEN NULL
					ELSE md5(lower(regexp_replace(sql_text, '\s+', ' ', 'g')))
				END AS sql_hash
			FROM source_events
		)
		INSERT INTO process_pg_events (
			host, pg_event_id, timestamp, pid, tid, uid, gid, comm, msg_type, data, container_id,
			exec_id, root_exec_id, root_pid, depth, sql_text, sql_hash
		)
		SELECT
			host, pg_event_id, timestamp, pid, tid, uid, gid, comm, msg_type, data, container_id,
			exec_id, root_exec_id, root_pid, depth, sql_text, sql_hash
		FROM enriched
		ON CONFLICT (host, pg_event_id) DO UPDATE
		SET timestamp = EXCLUDED.timestamp,
			pid = EXCLUDED.pid,
			tid = EXCLUDED.tid,
			uid = EXCLUDED.uid,
			gid = EXCLUDED.gid,
			comm = EXCLUDED.comm,
			msg_type = EXCLUDED.msg_type,
			data = EXCLUDED.data,
			container_id = EXCLUDED.container_id,
			exec_id = EXCLUDED.exec_id,
			root_exec_id = EXCLUDED.root_exec_id,
			root_pid = EXCLUDED.root_pid,
			depth = EXCLUDED.depth,
			sql_text = EXCLUDED.sql_text,
			sql_hash = EXCLUDED.sql_hash;
	`, host, since, until)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "42P01" || pgErr.Code == "42883") {
			// Optional feature: allow analysis to proceed if Postgres tables/functions
			// are not yet migrated.
			return nil
		}
	}
	return err
}

func (s *Scheduler) populateProcessS3(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	_, err := tx.Exec(ctx, `
			WITH req_stream AS (
				SELECT
					q.host,
					q.pid,
					q.tid,
					q.id AS request_id,
					q.timestamp AS req_ts,
					lead(q.timestamp) OVER (PARTITION BY q.host, q.pid, q.tid ORDER BY q.timestamp) AS next_req_ts,
					q.method,
					q.url,
					q.content_length,
					q.headers,
					q.container_id
				FROM http_request q
				WHERE q.host = $1
				  AND q.timestamp > ($2::timestamptz - interval '2 minutes') AND q.timestamp <= $3::timestamptz
				  AND (
					(q.headers ? 'X-Amz-Date') OR (q.headers ? 'x-amz-date')
					OR (q.headers ? 'X-Amz-Content-Sha256') OR (q.headers ? 'x-amz-content-sha256')
					OR (q.headers ? 'X-Amz-Security-Token') OR (q.headers ? 'x-amz-security-token')
					OR (q.url ILIKE '%X-Amz-Algorithm=AWS4-HMAC-SHA256%')
					OR (q.url ILIKE '%x-amz-algorithm=AWS4-HMAC-SHA256%')
				  )
			),
			resp_candidates AS (
				SELECT
					r.host,
					r.id AS response_id,
					r.timestamp,
					r.pid,
					r.tid,
					r.comm,
					r.status_code::int AS status_code,
					r.content_length AS response_bytes,
					r.headers AS response_headers,
					r.body AS response_body,
					r.container_id AS response_container_id
				FROM http_response r
				WHERE r.host = $1
				  AND r.timestamp > $2::timestamptz AND r.timestamp <= $3::timestamptz
				  AND (
					(r.headers ? 'X-Amz-Request-Id') OR (r.headers ? 'x-amz-request-id')
					OR (r.headers->>'Server' = 'AmazonS3') OR (r.headers->>'server' = 'AmazonS3')
				  )
			),
			with_request AS (
				SELECT
					resp.*,
					req.request_id,
					req.method,
					req.url,
					req.content_length AS request_bytes,
					req.headers AS request_headers,
					req.container_id AS request_container_id
				FROM resp_candidates resp
				LEFT JOIN LATERAL (
					SELECT
						r.request_id,
						r.method,
						r.url,
						r.content_length,
						r.headers,
						r.container_id
					FROM req_stream r
					WHERE r.host = resp.host
					  AND r.pid = resp.pid
					  AND r.tid = resp.tid
					  AND r.req_ts <= resp.timestamp
					  AND resp.timestamp < coalesce(r.next_req_ts, r.req_ts + interval '2 minutes')
					ORDER BY r.req_ts DESC
					LIMIT 1
				) req ON TRUE
			),
			parsed AS (
				SELECT
					w.host,
					w.response_id,
					w.request_id,
					w.timestamp,
					w.pid,
					w.tid,
					w.comm,
					w.method,
					w.url,
					w.status_code,
					w.request_bytes,
					w.response_bytes,
					coalesce(w.response_container_id, w.request_container_id) AS container_id,
					l.exec_id,
					l.root_exec_id,
					l.root_pid,
					l.depth,
					lower(
						coalesce(
							nullif(coalesce(w.request_headers->>'Host', w.request_headers->>'host', w.request_headers->>':authority'), ''),
							nullif(substring(coalesce(w.url, '') from '^https?://([^/]+)'), ''),
							''
						)
					) AS authority,
					ltrim(regexp_replace(split_part(coalesce(w.url, ''), '?', 1), '^https?://[^/]+', ''), '/') AS path_no_query,
					coalesce(w.response_headers->>'x-amz-bucket-region', w.response_headers->>'X-Amz-Bucket-Region') AS bucket_region_header,
					safe_text_from_bytea(w.response_body) AS response_body_text
				FROM with_request w
				LEFT JOIN process_lifecycle l
				  ON l.host = w.host AND l.pid = w.pid
				 AND w.timestamp BETWEEN l.start_ts AND (l.end_ts + analyze_idle_timeout())
			),
			enriched AS (
				SELECT
					p.*,
					coalesce(
						nullif(
							CASE
								WHEN p.authority ~ '\\.s3(\\.[a-z0-9-]+)?\\.amazonaws\\.com$' THEN regexp_replace(p.authority, '\\.s3(\\.[a-z0-9-]+)?\\.amazonaws\\.com$', '')
								WHEN p.authority ~ '^s3(\\.[a-z0-9-]+)?\\.amazonaws\\.com$' THEN nullif(split_part(p.path_no_query, '/', 1), '')
								ELSE NULL
							END,
							''
						),
						nullif(substring(p.response_body_text from '<BucketName>([^<]+)</BucketName>'), ''),
						nullif(substring(p.response_body_text from '(?s)<ListBucketResult.*?<Name>([^<]+)</Name>'), '')
					) AS bucket,
					CASE
						WHEN p.authority ~ '\\.s3(\\.[a-z0-9-]+)?\\.amazonaws\\.com$' THEN nullif(p.path_no_query, '')
						WHEN p.authority ~ '^s3(\\.[a-z0-9-]+)?\\.amazonaws\\.com$' THEN (
							CASE
								WHEN position('/' in p.path_no_query) > 0 THEN nullif(substring(p.path_no_query from position('/' in p.path_no_query) + 1), '')
								ELSE NULL
							END
						)
						ELSE NULL
					END AS object_key,
					coalesce(
						nullif(p.bucket_region_header, ''),
						substring(p.authority from '\\.s3\\.([a-z0-9-]+)\\.amazonaws\\.com$'),
						substring(p.authority from '^s3\\.([a-z0-9-]+)\\.amazonaws\\.com$')
					) AS bucket_region,
					CASE
						-- ListObjectsV2: response body contains <ListBucketResult> XML
						WHEN p.response_body_text ~ '<ListBucketResult' THEN 'ListObjectsV2'
						-- DeleteObject: status 204 with no body
						WHEN p.status_code = 204 THEN 'DeleteObject'
						-- HeadObject: status 200 with empty/minimal body
						WHEN p.status_code = 200 
							AND (p.response_bytes IS NULL OR p.response_bytes = 0)
							AND (p.response_body_text IS NULL OR p.response_body_text = '') THEN 'HeadObject'
						-- PutObject: status 200/204 with ETag header and empty/small body
						WHEN p.status_code IN (200, 204)
							AND (p.response_bytes IS NULL OR p.response_bytes <= 100)
							AND p.response_body_text !~ '<ListBucketResult' THEN 'PutObject'
						-- GetObject: status 200 with actual content body
						WHEN p.status_code = 200 
							AND p.response_bytes > 0 THEN 'GetObject'
						ELSE NULL
					END AS operation
				FROM parsed p
			)
			INSERT INTO process_s3_events (
				host, response_id, request_id, timestamp, pid, tid, comm,
				method, url, status_code, bucket, bucket_region, object_key,
				request_bytes, response_bytes, container_id,
				exec_id, root_exec_id, root_pid, depth, operation
			)
			SELECT
				host, response_id, request_id, timestamp, pid, tid, comm,
				method, url, status_code, bucket, bucket_region, object_key,
				request_bytes, response_bytes, container_id,
				exec_id, root_exec_id, root_pid, depth, operation
			FROM enriched
			ON CONFLICT (host, response_id) DO UPDATE
			SET request_id = EXCLUDED.request_id,
				timestamp = EXCLUDED.timestamp,
				pid = EXCLUDED.pid,
				tid = EXCLUDED.tid,
				comm = EXCLUDED.comm,
				method = EXCLUDED.method,
				url = EXCLUDED.url,
				status_code = EXCLUDED.status_code,
				bucket = EXCLUDED.bucket,
				bucket_region = EXCLUDED.bucket_region,
				object_key = EXCLUDED.object_key,
			request_bytes = EXCLUDED.request_bytes,
			response_bytes = EXCLUDED.response_bytes,
			container_id = EXCLUDED.container_id,
			exec_id = EXCLUDED.exec_id,
			root_exec_id = EXCLUDED.root_exec_id,
			root_pid = EXCLUDED.root_pid,
			depth = EXCLUDED.depth,
			operation = EXCLUDED.operation;
		`, host, since, until)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			// Optional feature: allow analysis to proceed if S3 derivation tables are not yet migrated.
			return nil
		}
	}
	return err
}

func (s *Scheduler) refreshProcessLifecycle(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	_, err := tx.Exec(ctx, `SELECT refresh_process_lifecycle_incremental($1, $2, $3)`, host, since, until)
	return err
}

func (s *Scheduler) populateLLMHTTP(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	_, err := tx.Exec(ctx, `SELECT populate_llm_http_events($1, $2, $3)`, host, since, until)
	return err
}

func (s *Scheduler) populateCorrelationSummary(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO correlation_summary (
			host, response_id, response_ts, status_code, method, url,
			root_exec_id, root_pid, best_event_id, best_event_exec_id,
			event_root_exec_id, event_root_pid, best_event_comm, best_event_args,
			best_total_score, best_correlation_type, best_gap_ms,
			best_lineage_score, best_temporal_score, best_argument_score,
			best_argument_match_flag, system_actions, evidence
		)
		SELECT
			resp.host,
			resp.id,
			resp.timestamp,
			resp.status_code::int,
			req.method,
			req.url,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL::jsonb,
			NULL::jsonb
		FROM http_response resp
		LEFT JOIN LATERAL (
			SELECT q.method, q.url
			FROM http_request q
			WHERE q.host = resp.host
			  AND q.pid = resp.pid
			  AND q.timestamp <= resp.timestamp
			ORDER BY q.timestamp DESC
			LIMIT 1
		) req ON TRUE
		WHERE resp.host = $1 AND resp.timestamp > $2 AND resp.timestamp <= $3
		ON CONFLICT (host, response_id) DO UPDATE
		SET response_ts = EXCLUDED.response_ts,
			status_code = EXCLUDED.status_code,
			method = EXCLUDED.method,
			url = EXCLUDED.url;
	`, host, since, until)
	return err
}

func (s *Scheduler) populateHeuristicAlerts(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO heuristic_alerts (
			alert_id, alert_type, host, severity, score, start_ts, end_ts,
			root_exec_id, root_pid, details
		)
		SELECT
			CONCAT('http_5xx:', resp.host, ':', resp.id::text),
			'http_5xx',
			resp.host,
			'medium',
			NULL,
			resp.timestamp,
			NULL,
			NULL,
			NULL,
			json_build_object(
				'summary', 'HTTP 5xx response detected',
				'status_code', resp.status_code
			)::jsonb
		FROM http_response resp
		WHERE resp.host = $1
		  AND resp.timestamp > $2 AND resp.timestamp <= $3
		  AND resp.status_code >= 500
		ON CONFLICT (alert_id) DO UPDATE
		SET severity = EXCLUDED.severity,
			score = EXCLUDED.score,
			start_ts = EXCLUDED.start_ts,
			end_ts = EXCLUDED.end_ts,
			root_exec_id = EXCLUDED.root_exec_id,
			root_pid = EXCLUDED.root_pid,
			details = EXCLUDED.details;
	`, host, since, until)
	return err
}

func (s *Scheduler) populateAgentHierarchy(ctx context.Context, tx pgx.Tx, host string, since, until time.Time) error {
	_, err := tx.Exec(ctx, `SELECT upsert_agent_hierarchy($1, $2, $3)`, host, since, until)
	return err
}

func (s *Scheduler) updateWatermark(ctx context.Context, tx pgx.Tx, host string, until time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE analysis_watermark SET last_response_ts = $2 WHERE host = $1`, host, until)
	return err
}
