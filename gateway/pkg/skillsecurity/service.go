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
		strategy = "auto"
	}
	prompt = strings.TrimSpace(prompt)
	if prompt == "" && strategy != "explicit" {
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

func timestamptzNow(now func() time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: now().UTC(), Valid: true}
}
