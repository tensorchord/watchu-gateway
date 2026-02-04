package skillsecurity

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/parser"
)

// ExecutionTraceService handles parsing and storing execution traces
type ExecutionTraceService struct {
	queries       *sqlc.Queries
	parserFactory *parser.ParserFactory
	logger        *slog.Logger
}

// NewExecutionTraceService creates a new execution trace service
func NewExecutionTraceService(queries *sqlc.Queries, logger *slog.Logger) *ExecutionTraceService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ExecutionTraceService{
		queries:       queries,
		parserFactory: parser.NewParserFactory(),
		logger:        logger,
	}
}

// ParseAndStore parses runner_output and stores to database
func (s *ExecutionTraceService) ParseAndStore(ctx context.Context, analysisID pgtype.UUID) error {
	// 1. Get skill analysis to check if already parsed
	exists, err := s.queries.CheckExecutionTraceExists(ctx, analysisID)
	if err != nil {
		s.logger.Error("failed to check execution trace existence",
			slog.String("analysis_id", analysisID.String()),
			slog.Any("error", err))
		return err
	}
	if exists {
		s.logger.Debug("execution trace already exists, skipping",
			slog.String("analysis_id", analysisID.String()))
		return nil
	}

	// 2. Get skill analysis data
	analysis, err := s.queries.GetSkillAnalysisByID(ctx, analysisID)
	if err != nil {
		return err
	}

	runnerOutput := analysis.RunnerOutput.String
	agentType := analysis.AgentType

	if runnerOutput == "" {
		s.logger.Debug("no runner output to parse",
			slog.String("analysis_id", analysisID.String()))
		return nil
	}

	// 3. Get parser
	p, err := s.parserFactory.GetParser(parser.AgentType(agentType))
	if err != nil {
		s.logger.Warn("unsupported agent type for parsing",
			slog.String("agent_type", agentType),
			slog.String("analysis_id", analysisID.String()))
		return err
	}

	// 4. Parse into event list
	events, err := p.Parse(runnerOutput)
	if err != nil {
		return err
	}

	// 5. Build execution trace
	tracer := parser.NewExecutionTracer(analysisID.String())
	trace, err := tracer.Trace(events)
	if err != nil {
		return err
	}

	// 6. Serialize to JSON
	toolCallsJSON, err := json.Marshal(trace.ToolCalls)
	if err != nil {
		return err
	}
	fileAccessJSON, err := json.Marshal(trace.FileAccess)
	if err != nil {
		return err
	}
	externalAccessJSON, err := json.Marshal(trace.ExternalAccess)
	if err != nil {
		return err
	}
	timelineJSON, err := json.Marshal(trace.Timeline)
	if err != nil {
		return err
	}
	errorsJSON, err := json.Marshal(trace.Errors)
	if err != nil {
		return err
	}
	securityAlertsJSON, err := json.Marshal(trace.SecurityAlerts)
	if err != nil {
		return err
	}

	// 7. Insert to database
	_, err = s.queries.InsertExecutionTrace(ctx, sqlc.InsertExecutionTraceParams{
		AnalysisID:         analysisID,
		SessionID:          pgtype.Text{String: trace.SessionID, Valid: trace.SessionID != ""},
		Status:             pgtype.Text{String: trace.Status, Valid: trace.Status != ""},
		DurationMs:         pgtype.Int4{Int32: int32(trace.DurationMS), Valid: true},
		NumTurns:           pgtype.Int4{Int32: int32(trace.NumTurns), Valid: true},
		TotalCostUsd:       pgtype.Numeric{Valid: false}, // TODO: convert float64 to pgtype.Numeric
		ToolCalls:          toolCallsJSON,
		FileAccess:         fileAccessJSON,
		ExternalAccess:     externalAccessJSON,
		Timeline:           timelineJSON,
		Errors:             errorsJSON,
		SecurityAlerts:     securityAlertsJSON,
		TotalToolCalls:     pgtype.Int4{Int32: int32(len(trace.ToolCalls)), Valid: true},
		TotalFileAccess:    pgtype.Int4{Int32: int32(len(trace.FileAccess)), Valid: true},
		TotalExternalAccess: pgtype.Int4{Int32: int32(len(trace.ExternalAccess)), Valid: true},
		TotalErrors:        pgtype.Int4{Int32: int32(len(trace.Errors)), Valid: true},
		TotalSecurityAlerts: pgtype.Int4{Int32: int32(len(trace.SecurityAlerts)), Valid: true},
		ParserVersion:      pgtype.Text{String: "1.0.0", Valid: true},
	})

	if err != nil {
		return err
	}

	s.logger.Info("execution trace parsed and stored",
		slog.String("analysis_id", analysisID.String()),
		slog.Int("tool_calls", len(trace.ToolCalls)),
		slog.Int("file_access", len(trace.FileAccess)),
		slog.Int("errors", len(trace.Errors)))

	return nil
}

// OnSkillAnalysisCompleted is called when skill analysis completes
// This triggers async parsing of the execution trace
func (s *ExecutionTraceService) OnSkillAnalysisCompleted(ctx context.Context, analysisID pgtype.UUID) {
	// Execute parsing task asynchronously
	go func() {
		if err := s.ParseAndStore(context.Background(), analysisID); err != nil {
			s.logger.Error("failed to parse execution trace",
				slog.String("analysis_id", analysisID.String()),
				slog.Any("error", err))
		}
	}()
}

// GetExecutionTrace retrieves execution trace
func (s *ExecutionTraceService) GetExecutionTrace(ctx context.Context, analysisID pgtype.UUID) (*parser.ExecutionTrace, error) {
	row, err := s.queries.GetExecutionTraceByAnalysisID(ctx, analysisID)
	if err != nil {
		return nil, err
	}

	trace := &parser.ExecutionTrace{
		AnalysisID:   analysisID.String(),
		SessionID:    row.SessionID.String,
		Status:       row.Status.String,
		DurationMS:   int(row.DurationMs.Int32),
		NumTurns:     int(row.NumTurns.Int32),
		TotalCostUSD: 0, // TODO: convert pgtype.Numeric to float64
	}

	json.Unmarshal(row.ToolCalls, &trace.ToolCalls)
	json.Unmarshal(row.FileAccess, &trace.FileAccess)
	json.Unmarshal(row.ExternalAccess, &trace.ExternalAccess)
	json.Unmarshal(row.Timeline, &trace.Timeline)
	json.Unmarshal(row.Errors, &trace.Errors)
	json.Unmarshal(row.SecurityAlerts, &trace.SecurityAlerts)

	return trace, nil
}

// GetTimeline retrieves only timeline (partial query, faster)
func (s *ExecutionTraceService) GetTimeline(ctx context.Context, analysisID pgtype.UUID) ([]parser.TimelineEvent, error) {
	timelineJSON, err := s.queries.GetTimelineByAnalysisID(ctx, analysisID)
	if err != nil {
		return nil, err
	}

	var timeline []parser.TimelineEvent
	json.Unmarshal(timelineJSON, &timeline)
	return timeline, nil
}

// ExecutionTraceSummary represents a summary of execution trace
type ExecutionTraceSummary struct {
	AnalysisID       string         `db:"analysis_id"`
	SessionID        string         `db:"session_id"`
	Status           string         `db:"status"`
	DurationMS       int            `db:"duration_ms"`
	NumTurns         int            `db:"num_turns"`
	TotalToolCalls   int            `db:"total_tool_calls"`
	TotalFileAccess  int            `db:"total_file_access"`
	TotalErrors      int            `db:"total_errors"`
	SecurityAlerts   int            `db:"total_security_alerts"`
	ParsedAt         pgtype.Timestamptz `db:"parsed_at"`
}

// ListExecutionTraces lists execution traces with pagination
func (s *ExecutionTraceService) ListExecutionTraces(ctx context.Context, limit, offset int32) ([]sqlc.ListExecutionTracesRow, error) {
	return s.queries.ListExecutionTraces(ctx, sqlc.ListExecutionTracesParams{
		Limit:  limit,
		Offset: offset,
	})
}
