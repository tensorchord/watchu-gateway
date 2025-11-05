package ingest

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service persists ingress events into PostgreSQL.
type Service struct {
	pool *pgxpool.Pool
}

// NewService creates a Service backed by the provided pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// IngestHTTPRequests copies HTTP request events into storage.
func (s *Service) IngestHTTPRequests(ctx context.Context, events []HTTPRequestEvent) error {
	if len(events) == 0 {
		return nil
	}

	rows := make([][]any, len(events))
	for i, event := range events {
		rows[i] = []any{
			event.Timestamp,
			event.PID,
			event.TID,
			event.UID,
			event.GID,
			event.Comm,
			event.Method,
			nilIfNil(event.ContentLength),
			event.URL,
			event.Protocol,
			event.Headers,
			event.Body,
			event.Truncated,
			event.Host,
		}
	}

	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"http_request"}, httpRequestCols, pgx.CopyFromRows(rows))
	return err
}

// IngestHTTPResponses copies HTTP response events into storage.
func (s *Service) IngestHTTPResponses(ctx context.Context, events []HTTPResponseEvent) error {
	if len(events) == 0 {
		return nil
	}

	rows := make([][]any, len(events))
	for i, event := range events {
		rows[i] = []any{
			event.Timestamp,
			event.PID,
			event.TID,
			event.UID,
			event.GID,
			event.Comm,
			event.StatusCode,
			nilIfNil(event.ContentLength),
			event.Protocol,
			event.Headers,
			event.Body,
			event.Truncated,
			event.Host,
		}
	}

	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"http_response"}, httpResponseCols, pgx.CopyFromRows(rows))
	return err
}

// IngestExecEvents copies exec lifecycle events into storage.
func (s *Service) IngestExecEvents(ctx context.Context, events []ExecEvent) error {
	if len(events) == 0 {
		return nil
	}

	rows := make([][]any, len(events))
	for i, event := range events {
		rows[i] = []any{
			event.Timestamp,
			event.PID,
			event.PPID,
			event.ExecID,
			event.PExecID,
			event.CWD,
			event.Comm,
			event.Args,
			event.Host,
		}
	}

	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"exec_events"}, execEventCols, pgx.CopyFromRows(rows))
	return err
}

func nilIfNil(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}
