package analysis

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Scheduler periodically drives incremental analysis in the database.
type Scheduler struct {
	pool     *pgxpool.Pool
	interval time.Duration
	lookback time.Duration
	horizon  time.Duration
	lag      time.Duration
	logger   *slog.Logger
	now      func() time.Time
}

// NewScheduler wires scheduler configuration with dependencies.
func NewScheduler(pool *pgxpool.Pool, interval, lookback, horizon, lag time.Duration, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		pool:     pool,
		interval: interval,
		lookback: lookback,
		horizon:  horizon,
		lag:      lag,
		logger:   logger,
		now:      time.Now,
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
	rows, err := s.pool.Query(ctx, `
			SELECT DISTINCT host
			FROM (
				SELECT host FROM http_response WHERE timestamp >= $1
				UNION ALL
				SELECT host FROM http_request WHERE timestamp >= $1
			) recent
		`, since)
	if err != nil {
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

func (s *Scheduler) runAnalysis(ctx context.Context, host string) error {
	until := s.now().Add(-s.lag)
	if until.IsZero() {
		return nil
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

	if !windowSince.Before(until) {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return nil
	}

	if err := s.populateProcessHTTP(ctx, tx, host, windowSince, until); err != nil {
		return err
	}
	if err := s.populateCorrelationSummary(ctx, tx, host, windowSince, until); err != nil {
		return err
	}
	if err := s.populateHeuristicAlerts(ctx, tx, host, windowSince, until); err != nil {
		return err
	}

	if err := s.updateWatermark(ctx, tx, host, until); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Scheduler) ensureWatermark(ctx context.Context, tx pgx.Tx, host string, until time.Time) (time.Time, time.Time, error) {
	var last time.Time
	err := tx.QueryRow(ctx, `SELECT last_response_ts FROM analysis_watermark WHERE host = $1`, host).Scan(&last)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			last = until
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
	if _, err := tx.Exec(ctx, `
		INSERT INTO process_http_events (
			host, http_id, http_type, timestamp, pid, tid, method, url, status_code,
			protocol, headers, body, truncated, exec_id, root_exec_id, root_pid,
			depth, is_mcp_http
		)
		SELECT
			r.host,
			r.id,
			'request',
			r.timestamp,
			r.pid,
			r.tid,
			r.method,
			r.url,
			NULL,
			r.protocol,
			r.headers,
			r.body,
			r.truncated,
			NULL,
			NULL,
			NULL,
			NULL,
			FALSE
		FROM http_request r
		WHERE r.host = $1 AND r.timestamp > $2 AND r.timestamp <= $3
		ON CONFLICT (host, http_id, http_type) DO UPDATE
		SET timestamp = EXCLUDED.timestamp,
			pid = EXCLUDED.pid,
			tid = EXCLUDED.tid,
			method = EXCLUDED.method,
			url = EXCLUDED.url,
			protocol = EXCLUDED.protocol,
			headers = EXCLUDED.headers,
			body = EXCLUDED.body,
			truncated = EXCLUDED.truncated;
	`, host, since, until); err != nil {
		return err
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO process_http_events (
			host, http_id, http_type, timestamp, pid, tid, method, url, status_code,
			protocol, headers, body, truncated, exec_id, root_exec_id, root_pid,
			depth, is_mcp_http
		)
		SELECT
			resp.host,
			resp.id,
			'response',
			resp.timestamp,
			resp.pid,
			resp.tid,
			req.method,
			req.url,
			resp.status_code,
			resp.protocol,
			resp.headers,
			resp.body,
			resp.truncated,
			NULL,
			NULL,
			NULL,
			NULL,
			FALSE
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
			truncated = EXCLUDED.truncated;
	`, host, since, until)
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
			NULL
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
			alert_id, host, start_ts, root_exec_id, root_pid, status_code, details
		)
		SELECT
			CONCAT('http_5xx:', resp.host, ':', resp.id::text),
			resp.host,
			resp.timestamp,
			NULL,
			NULL,
			resp.status_code::int,
			json_build_object(
				'summary', 'HTTP 5xx response detected',
				'status_code', resp.status_code
			)::jsonb
		FROM http_response resp
		WHERE resp.host = $1
		  AND resp.timestamp > $2 AND resp.timestamp <= $3
		  AND resp.status_code >= 500
		ON CONFLICT (alert_id) DO UPDATE
		SET start_ts = EXCLUDED.start_ts,
			status_code = EXCLUDED.status_code,
			details = EXCLUDED.details;
	`, host, since, until)
	return err
}

func (s *Scheduler) updateWatermark(ctx context.Context, tx pgx.Tx, host string, until time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE analysis_watermark SET last_response_ts = $2 WHERE host = $1`, host, until)
	return err
}
