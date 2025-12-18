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
			event.ContentLength,
			event.URL,
			event.Protocol,
			event.Headers,
			event.Body,
			event.Truncated,
			event.Host,
			event.ContainerID,
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
			event.ContentLength,
			event.Protocol,
			event.Headers,
			event.Body,
			event.Truncated,
			event.Host,
			event.ContainerID,
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
			event.ContainerID,
		}
	}

	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"exec_events"}, execEventCols, pgx.CopyFromRows(rows))
	return err
}

// IngestMCPSTDIOEvents copies STDIO-based MCP JSON-RPC events into storage.
func (s *Service) IngestMCPSTDIOEvents(ctx context.Context, events []MCPSTDIOEvent) error {
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
			event.Host,
			event.MessageType,
			event.JSONRPC,
			event.Method,
			event.Params,
			event.Result,
			event.Error,
			event.CorrID,
			event.ContainerID,
		}
	}

	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"mcp_stdio_event"}, mcpSTDIOEventCols, pgx.CopyFromRows(rows))
	return err
}

// IngestPGEvents copies Postgres client protocol events into storage.
func (s *Service) IngestPGEvents(ctx context.Context, events []PGEvent) error {
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
			event.Host,
			event.Comm,
			event.MsgType,
			event.Data,
			event.ContainerID,
		}
	}

	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"pg_event"}, pgEventCols, pgx.CopyFromRows(rows))
	return err
}

// ContentLength is now a value type (int64); unknown length should be
// represented by -1 following net/http semantics and stored as such.
