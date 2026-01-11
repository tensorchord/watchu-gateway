package skillsecurity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/securityinsight"
)

var ErrRunnerNotConfigured = errors.New("skill runner not configured")

type Runner interface {
	StartRun(ctx context.Context, req RunnerRequest) (*RunnerResponse, error)
	GetRun(ctx context.Context, runID string) (*RunnerRunDetail, error)
}

type Service struct {
	queries  *sqlc.Queries
	runner   Runner
	security *securityinsight.Service
	logger   *slog.Logger
	now      func() time.Time
}

type CreateRunInput struct {
	SourceType     string
	SourceRef      string
	ResolvedRef    string
	ArtifactPath   string
	AgentType      string
	RunnerMode     string
	PromptStrategy string
	PromptInput    string
}

func NewService(queries *sqlc.Queries, runner Runner, security *securityinsight.Service, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		queries:  queries,
		runner:   runner,
		security: security,
		logger:   logger,
		now:      time.Now,
	}
}

func (s *Service) CreateRun(ctx context.Context, input CreateRunInput) (sqlc.SkillSecurityRun, error) {
	if s.queries == nil {
		return sqlc.SkillSecurityRun{}, fmt.Errorf("queries not configured")
	}

	agentType := strings.TrimSpace(input.AgentType)
	if agentType == "" {
		agentType = "claude-code"
	}

	promptStrategy, promptInput := normalizePrompt(input.PromptStrategy, input.PromptInput)

	run, err := s.queries.InsertSkillSecurityRun(ctx, sqlc.InsertSkillSecurityRunParams{
		SourceType:     strings.TrimSpace(input.SourceType),
		SourceRef:      strings.TrimSpace(input.SourceRef),
		ResolvedRef:    textOrNull(input.ResolvedRef),
		ArtifactPath:   textOrNull(input.ArtifactPath),
		AgentType:      agentType,
		RunnerMode:     strings.TrimSpace(input.RunnerMode),
		PromptStrategy: promptStrategy,
		PromptInput:    textOrNull(promptInput),
		Status:         "pending",
		Error:          pgtype.Text{},
		RunnerRunID:    pgtype.Text{},
		RunnerOutput:   pgtype.Text{},
		RunnerExitCode: pgtype.Int4{},
		RootExecID:     pgtype.Text{},
		AgentRunID:     pgtype.UUID{},
	})
	if err != nil {
		return sqlc.SkillSecurityRun{}, err
	}

	if s.runner == nil {
		_ = s.updateStatus(ctx, run.ID, "failed", ErrRunnerNotConfigured.Error())
		return run, ErrRunnerNotConfigured
	}

	resp, err := s.runner.StartRun(ctx, RunnerRequest{
		SourceType:     input.SourceType,
		SourceRef:      input.SourceRef,
		ResolvedRef:    input.ResolvedRef,
		ArtifactPath:   input.ArtifactPath,
		AgentType:      agentType,
		RunnerMode:     input.RunnerMode,
		PromptStrategy: promptStrategy,
		PromptInput:    promptInput,
	})
	if err != nil {
		_ = s.updateStatus(ctx, run.ID, "failed", err.Error())
		return run, err
	}

	status := strings.TrimSpace(resp.Status)
	if status == "" {
		status = "running"
	}
	if resp.Error != "" {
		status = "failed"
	}

	rootExecID := strings.TrimSpace(resp.RootExecID)
	runnerRunID := strings.TrimSpace(resp.RunID)
	if runnerRunID != "" {
		_ = s.queries.UpdateSkillSecurityRunRunner(ctx, sqlc.UpdateSkillSecurityRunRunnerParams{
			ID:          run.ID,
			RunnerRunID: textOrNull(runnerRunID),
			UpdatedAt:   timestamptzNow(s.now),
		})
		go s.pollRunnerStatus(run.ID, runnerRunID, run.CreatedAt, agentType)
	}
	var agentRunID pgtype.UUID
	if rootExecID != "" {
		if found, lookupErr := s.lookupAgentRunID(ctx, rootExecID); lookupErr == nil {
			agentRunID = found
		}
		_ = s.queries.UpdateSkillSecurityRunRootExec(ctx, sqlc.UpdateSkillSecurityRunRootExecParams{
			ID:         run.ID,
			RootExecID: textOrNull(rootExecID),
			AgentRunID: agentRunID,
			Status:     status,
			UpdatedAt:  timestamptzNow(s.now),
		})
	} else {
		_ = s.updateStatus(ctx, run.ID, status, resp.Error)
	}

	if status == "completed" && rootExecID != "" && s.security != nil {
		if _, err := s.security.AnalyzeThreat(ctx, rootExecID); err != nil {
			s.logger.Warn("skill security threat analysis failed", slog.String("root_exec_id", rootExecID), slog.String("error", err.Error()))
		}
	}

	updated, err := s.queries.GetSkillSecurityRunByID(ctx, run.ID)
	if err != nil {
		return run, nil
	}
	return updated, nil
}

func (s *Service) GetRun(ctx context.Context, id pgtype.UUID) (sqlc.SkillSecurityRun, error) {
	return s.queries.GetSkillSecurityRunByID(ctx, id)
}

func (s *Service) ListRuns(ctx context.Context, status, sourceType string, limit, offset int32) ([]sqlc.SkillSecurityRun, error) {
	return s.queries.ListSkillSecurityRuns(ctx, sqlc.ListSkillSecurityRunsParams{
		Status:     status,
		SourceType: sourceType,
		Limit:      limit,
		Offset:     offset,
	})
}

type SkillSummary struct {
	SourceType      string
	SourceRef       string
	ArtifactPath    string
	LastRunAt       *time.Time
	RunCount        int64
	LastRunnerMode  string
}

func (s *Service) ListSkills(ctx context.Context, sourceType string, limit int32) ([]SkillSummary, error) {
	if s.queries == nil {
		return nil, fmt.Errorf("queries not configured")
	}
	rows, err := s.queries.ListSkills(ctx, sqlc.ListSkillsParams{
		SourceType: sourceType,
		Limit:      limit,
	})
	if err != nil {
		return nil, err
	}
	result := make([]SkillSummary, 0, len(rows))
	for _, row := range rows {
		var lastRun *time.Time
		if row.LastRunAt != nil {
			if ts, ok := row.LastRunAt.(time.Time); ok && !ts.IsZero() {
				lastRun = &ts
			}
		}
		var lastRunnerMode string
		if row.LastRunnerMode != nil {
			if mode, ok := row.LastRunnerMode.(string); ok {
				lastRunnerMode = mode
			}
		}
		// Default to local if no previous run
		if lastRunnerMode == "" {
			lastRunnerMode = "local"
		}
		result = append(result, SkillSummary{
			SourceType:      row.SourceType,
			SourceRef:       row.SourceRef,
			ArtifactPath:    stringFromText(row.ArtifactPath),
			LastRunAt:       lastRun,
			RunCount:        row.RunCount,
			LastRunnerMode:  lastRunnerMode,
		})
	}
	return result, nil
}

func (s *Service) GetSkillRuns(ctx context.Context, sourceRef, artifactPath string) ([]sqlc.SkillSecurityRun, error) {
	if s.queries == nil {
		return nil, fmt.Errorf("queries not configured")
	}
	return s.queries.GetSkillRuns(ctx, sqlc.GetSkillRunsParams{
		SourceRef:    sourceRef,
		ArtifactPath: textOrNull(artifactPath),
	})
}

func (s *Service) pollRunnerStatus(runID pgtype.UUID, runnerRunID string, createdAt pgtype.Timestamptz, agentType string) {
	if s.runner == nil {
		return
	}
	const (
		pollInterval = 5 * time.Second
		maxErrors    = 3
	)
	deadline := time.Now().Add(30 * time.Minute)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	errorCount := 0
	ctx := context.Background()

	for {
		if time.Now().After(deadline) {
			_ = s.updateStatus(ctx, runID, "failed", "runner status timeout")
			return
		}
		<-ticker.C

		detail, err := s.runner.GetRun(ctx, runnerRunID)
		if err != nil {
			errorCount++
			if errorCount >= maxErrors {
				_ = s.updateStatus(ctx, runID, "failed", err.Error())
				return
			}
			continue
		}
		errorCount = 0

		status := strings.TrimSpace(detail.Status)
		if status == "" {
			status = "running"
		}
		if detail.Error != "" {
			status = "failed"
		}

		rootExecID := strings.TrimSpace(detail.RootExecID)
		runnerOutput := strings.TrimSpace(detail.Output)
		exitCode := detail.ExitCode

		exitCodeVal := pgtype.Int4{}
		if status == "completed" || status == "failed" {
			exitCodeVal = pgtype.Int4{Int32: int32(exitCode), Valid: true}
		}

		match := rootExecMatch{}
		if status == "completed" || status == "failed" {
			match = s.inferRootExecID(ctx, detail.Pid, detail.StartedAt, createdAt, s.now(), rootExecID)
			if rootExecID == "" && match.RootExecID != "" {
				rootExecID = match.RootExecID
			}
			s.ensureAgentRunProvider(ctx, match, agentType)
		}

		var agentRunID pgtype.UUID
		if rootExecID != "" {
			if found, lookupErr := s.lookupAgentRunID(ctx, rootExecID); lookupErr == nil {
				agentRunID = found
			}
		}

		_ = s.queries.UpdateSkillSecurityRunResult(ctx, sqlc.UpdateSkillSecurityRunResultParams{
			ID:             runID,
			Status:         status,
			Error:          textOrNull(detail.Error),
			RunnerOutput:   textOrNull(runnerOutput),
			RunnerExitCode: exitCodeVal,
			RootExecID:     textOrNull(rootExecID),
			AgentRunID:     agentRunID,
			PromptInput:    textOrNull(detail.PromptInput),
			UpdatedAt:      timestamptzNow(s.now),
		})

		if status == "completed" || status == "failed" {
			// Step 1: Extract agent insights from runner output
			// This analyzes the agent's own logs for threat detection messages
			if runnerOutput != "" && s.security != nil {
				if err := s.security.ExtractAndStore(ctx, runID.Bytes, rootExecID, agentType, runnerOutput); err != nil {
					s.logger.Warn("agent insight extraction failed", slog.String("skill_run_id", fmt.Sprintf("%x", runID.Bytes)), slog.String("error", err.Error()))
				}
			}

			// Step 2: Run threat analysis using telemetry + extracted agent insights
			if status == "completed" && rootExecID != "" && s.security != nil {
				if _, err := s.security.AnalyzeThreat(ctx, rootExecID); err != nil {
					s.logger.Warn("skill security threat analysis failed", slog.String("root_exec_id", rootExecID), slog.String("error", err.Error()))
				}
			}
			return
		}
	}
}

type rootExecMatch struct {
	RootExecID string
	Host       string
	RootPid    int64
	StartedAt  time.Time
	EndedAt    time.Time
}

func (s *Service) inferRootExecID(ctx context.Context, pid int, startedAt time.Time, createdAt pgtype.Timestamptz, now time.Time, rootHint string) rootExecMatch {
	window := now
	if !startedAt.IsZero() {
		window = startedAt
	} else if createdAt.Valid {
		window = createdAt.Time
	}
	since := window.Add(-2 * time.Minute)
	until := window.Add(2 * time.Minute)

	hosts, err := s.queries.ListHosts(ctx, 10)
	if err != nil || len(hosts) == 0 {
		return rootExecMatch{}
	}

	if pid > 0 {
		for _, host := range hosts {
			rows, err := s.queries.ListProcessEventsByHostRange(ctx, sqlc.ListProcessEventsByHostRangeParams{
				Host:  host,
				Since: pgtype.Timestamptz{Time: since, Valid: true},
				Until: pgtype.Timestamptz{Time: until, Valid: true},
				Limit: 2000,
			})
			if err != nil {
				continue
			}
			for _, row := range rows {
				if !row.RootExecID.Valid || !row.Pid.Valid {
					continue
				}
				if int64(pid) != row.Pid.Int64 {
					continue
				}
				return rootExecMatch{
					RootExecID: strings.TrimSpace(row.RootExecID.String),
					Host:       host,
					RootPid:    int64FromRow(row.RootPid),
					StartedAt:  timeFromRow(row.StartTs),
					EndedAt:    timeFromRow(row.EndTs),
				}
			}
		}
	}

	if strings.TrimSpace(rootHint) != "" {
		for _, host := range hosts {
			rows, err := s.queries.ListProcessEventsByHostRange(ctx, sqlc.ListProcessEventsByHostRangeParams{
				Host:  host,
				Since: pgtype.Timestamptz{Time: since, Valid: true},
				Until: pgtype.Timestamptz{Time: until, Valid: true},
				Limit: 2000,
			})
			if err != nil {
				continue
			}
			for _, row := range rows {
				if !row.RootExecID.Valid || strings.TrimSpace(row.RootExecID.String) != rootHint {
					continue
				}
				return rootExecMatch{
					RootExecID: strings.TrimSpace(row.RootExecID.String),
					Host:       host,
					RootPid:    int64FromRow(row.RootPid),
					StartedAt:  timeFromRow(row.StartTs),
					EndedAt:    timeFromRow(row.EndTs),
				}
			}
		}
	}

	bestRoot := ""
	var bestTime time.Time
	bestMatch := rootExecMatch{}
	for _, host := range hosts {
		rows, err := s.queries.ListProcessEventsByHostRange(ctx, sqlc.ListProcessEventsByHostRangeParams{
			Host:  host,
			Since: pgtype.Timestamptz{Time: since, Valid: true},
			Until: pgtype.Timestamptz{Time: until, Valid: true},
			Limit: 5000,
		})
		if err != nil {
			continue
		}
		for _, row := range rows {
			if !row.RootExecID.Valid || !row.Comm.Valid || !row.StartTs.Valid {
				continue
			}
			if !strings.Contains(strings.ToLower(row.Comm.String), "claude") {
				continue
			}
			if bestRoot == "" || row.StartTs.Time.After(bestTime) {
				bestRoot = strings.TrimSpace(row.RootExecID.String)
				bestTime = row.StartTs.Time
				bestMatch = rootExecMatch{
					RootExecID: bestRoot,
					Host:       host,
					RootPid:    int64FromRow(row.RootPid),
					StartedAt:  timeFromRow(row.StartTs),
					EndedAt:    timeFromRow(row.EndTs),
				}
			}
		}
	}

	return bestMatch
}

func (s *Service) ensureAgentRunProvider(ctx context.Context, match rootExecMatch, agentType string) {
	agentType = strings.TrimSpace(agentType)
	if agentType == "" || match.RootExecID == "" || match.Host == "" {
		return
	}
	startedAt := match.StartedAt
	if startedAt.IsZero() {
		startedAt = s.now().UTC()
	}
	params := sqlc.UpsertAgentRunProviderParams{
		Host:       match.Host,
		RootExecID: textOrNull(match.RootExecID),
		RootPid:    int8OrNull(match.RootPid),
		Provider:   textOrNull(agentType),
		StartedAt:  pgtype.Timestamptz{Time: startedAt, Valid: true},
		EndedAt:    timestamptzOrNull(match.EndedAt),
	}
	if err := s.queries.UpsertAgentRunProvider(ctx, params); err != nil {
		s.logger.Warn("failed to upsert agent_run provider", slog.String("error", err.Error()))
	}
}

func int64FromRow(value pgtype.Int8) int64 {
	if !value.Valid {
		return 0
	}
	return value.Int64
}

func int8OrNull(value int64) pgtype.Int8 {
	if value <= 0 {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: value, Valid: true}
}

func timeFromRow(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time
}

func timestamptzOrNull(value time.Time) pgtype.Timestamptz {
	if value.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func (s *Service) updateStatus(ctx context.Context, id pgtype.UUID, status, errMsg string) error {
	return s.queries.UpdateSkillSecurityRunStatus(ctx, sqlc.UpdateSkillSecurityRunStatusParams{
		ID:        id,
		Status:    status,
		Error:     textOrNull(errMsg),
		UpdatedAt: timestamptzNow(s.now),
	})
}

func (s *Service) lookupAgentRunID(ctx context.Context, rootExecID string) (pgtype.UUID, error) {
	row, err := s.queries.GetAgentRunByRootExecID(ctx, textOrNull(rootExecID))
	if err != nil {
		return pgtype.UUID{}, err
	}
	return row.ID, nil
}

func normalizePrompt(strategy, prompt string) (string, string) {
	strategy = strings.TrimSpace(strategy)
	if strategy == "" {
		strategy = "from-skill"
	} else if strategy == "explicit" {
		strategy = "custom"
	}
	prompt = strings.TrimSpace(prompt)
	if prompt == "" && strategy != "custom" && strategy != "from-skill" {
		prompt = "Use the skill following SKILL.md instructions and run a minimal safe example."
	}
	return strategy, prompt
}

func textOrNull(value string) pgtype.Text {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: trimmed, Valid: true}
}

func stringFromText(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return strings.TrimSpace(value.String)
}

func timestamptzNow(now func() time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: now().UTC(), Valid: true}
}
