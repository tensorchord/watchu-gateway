package securityinsight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/promptinjection"
	"github.com/tensorchord/watchu/gateway/pkg/threatinsight"
)

// Service provides unified security insight capabilities including
// prompt injection detection and threat analysis
type Service struct {
	queries        *sqlc.Queries
	promptSvc      *promptinjection.Service
	threatDetector threatinsight.Detector
	threatModel    string
	logger         *slog.Logger
}

var ErrThreatInsightNotInitialized = errors.New("threat insight not initialized")

// Options configures the security insight service
type Options struct {
	PromptInjectionEnabled      bool
	PromptInjectionAPIBase      string
	PromptInjectionAPIKey       string
	PromptInjectionModel        string
	PromptInjectionMode         string
	PromptInjectionTimeout      time.Duration
	PromptInjectionBatchSize    int
	PromptInjectionMaxRetries   int
	PromptInjectionSampleRate   float64
	PromptInjectionMaxQPS       float64
	PromptInjectionMaxPromptLen int
	PromptInjectionStripTools   bool
	PromptInjectionExtractUser  bool

	ThreatInsightEnabled bool
	ThreatInsightBaseURL string
	ThreatInsightAPIKey  string
	ThreatInsightModel   string
	ThreatInsightTimeout time.Duration
}

// NewService creates a new unified security insight service
func NewService(queries *sqlc.Queries, opts Options, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}

	promptSvc := promptinjection.NewService(queries, promptinjection.Options{
		Enabled:           opts.PromptInjectionEnabled,
		APIBase:           opts.PromptInjectionAPIBase,
		APIKey:            opts.PromptInjectionAPIKey,
		Model:             opts.PromptInjectionModel,
		Mode:              opts.PromptInjectionMode,
		Timeout:           opts.PromptInjectionTimeout,
		BatchSize:         opts.PromptInjectionBatchSize,
		MaxRetries:        opts.PromptInjectionMaxRetries,
		SampleRate:        opts.PromptInjectionSampleRate,
		MaxQPS:            opts.PromptInjectionMaxQPS,
		MaxPromptLength:   opts.PromptInjectionMaxPromptLen,
		StripToolCalls:    opts.PromptInjectionStripTools,
		ExtractUserPrompt: opts.PromptInjectionExtractUser,
	}, logger)

	var threatDetector threatinsight.Detector
	var threatModel string
	if opts.ThreatInsightEnabled {
		var err error
		threatDetector, threatModel, err = initThreatInsight(queries, opts, logger)
		if err != nil {
			logger.Warn("threat insight disabled", slog.String("reason", err.Error()))
		}
	}

	return &Service{
		queries:        queries,
		promptSvc:      promptSvc,
		threatDetector: threatDetector,
		threatModel:    threatModel,
		logger:         logger,
	}, nil
}

// DetectPromptInjection runs prompt injection detection for a host within a time window
func (s *Service) DetectPromptInjection(ctx context.Context, host string, since, until time.Time) error {
	if s.promptSvc == nil {
		return fmt.Errorf("prompt injection detection not initialized")
	}
	return s.promptSvc.Run(ctx, host, since, until)
}

// GetThreatAnalysis retrieves the latest threat analysis result for a root execution ID from database
func (s *Service) GetThreatAnalysis(ctx context.Context, rootExecID string) (*threatinsight.AnalysisResult, error) {
	rootExecIDText := pgtype.Text{String: rootExecID, Valid: true}
	row, err := s.queries.GetLatestSecurityAnalysisByRootExecID(ctx, rootExecIDText)
	if err != nil {
		return nil, err
	}

	// Convert database row to AnalysisResult
	result := &threatinsight.AnalysisResult{
		ThreatLevel: int(row.ThreatLevel.Int32),
		ThreatType:  row.ThreatType.String,
		Confidence:  row.Confidence.Float64,
		Summary:     row.Summary.String,
		Details:     row.Details.String,
	}

	// Parse recommendations from JSONB
	if len(row.Recommendations) > 0 {
		var recommendations []string
		if err := json.Unmarshal(row.Recommendations, &recommendations); err == nil {
			result.Recommendations = recommendations
		}
	}

	// Parse evidence from JSONB
	if len(row.Evidence) > 0 {
		var evidence []map[string]interface{}
		if err := json.Unmarshal(row.Evidence, &evidence); err == nil {
			result.Evidence = evidence
		}
	}

	return result, nil
}

// AnalyzeThreat performs deep threat analysis on a root execution ID
// It first checks if a recent analysis exists in the database (within 24 hours)
// If found, returns the cached result; otherwise, performs new analysis
func (s *Service) AnalyzeThreat(ctx context.Context, rootExecID string) (*threatinsight.AnalysisResult, error) {
	if s.threatDetector == nil {
		return nil, ErrThreatInsightNotInitialized
	}

	// Check for existing analysis in the last 24 hours
	rootExecIDText := pgtype.Text{String: rootExecID, Valid: true}
	existingResult, err := s.queries.GetLatestSecurityAnalysisByRootExecID(ctx, rootExecIDText)
	if err == nil {
		// Found existing result, check if it's recent (within 24 hours)
		if time.Since(existingResult.AnalyzedAt.Time) < 24*time.Hour {
			s.logger.Info("using cached threat analysis result",
				slog.String("root_exec_id", rootExecID),
				slog.Time("analyzed_at", existingResult.AnalyzedAt.Time))

			// Convert to AnalysisResult and return
			result := &threatinsight.AnalysisResult{
				ThreatLevel: int(existingResult.ThreatLevel.Int32),
				ThreatType:  existingResult.ThreatType.String,
				Confidence:  existingResult.Confidence.Float64,
				Summary:     existingResult.Summary.String,
				Details:     existingResult.Details.String,
			}

			if len(existingResult.Recommendations) > 0 {
				var recommendations []string
				if err := json.Unmarshal(existingResult.Recommendations, &recommendations); err == nil {
					result.Recommendations = recommendations
				}
			}

			if len(existingResult.Evidence) > 0 {
				var evidence []map[string]interface{}
				if err := json.Unmarshal(existingResult.Evidence, &evidence); err == nil {
					result.Evidence = evidence
				}
			}

			return result, nil
		}
		s.logger.Info("existing analysis is stale, performing new analysis",
			slog.String("root_exec_id", rootExecID),
			slog.Duration("age", time.Since(existingResult.AnalyzedAt.Time)))
	}

	// No recent result found, perform new analysis
	s.logger.Info("performing new threat analysis", slog.String("root_exec_id", rootExecID))
	result, err := s.threatDetector.Analyze(ctx, rootExecID)
	if err != nil {
		return nil, err
	}

	// Save analysis result to database
	if saveErr := threatinsight.SaveAnalysisResult(ctx, s.queries, rootExecID, result); saveErr != nil {
		s.logger.Warn("failed to save threat analysis result", slog.String("root_exec_id", rootExecID), slog.String("error", saveErr.Error()))
	}

	return result, nil
}

// Ready checks if the service is ready for health checks
func (s *Service) Ready(ctx context.Context) error {
	if s.promptSvc != nil {
		return s.promptSvc.Ready(ctx)
	}
	return nil
}

// PromptInjectionService returns the underlying prompt injection service for scheduler
func (s *Service) PromptInjectionService() *promptinjection.Service {
	return s.promptSvc
}
