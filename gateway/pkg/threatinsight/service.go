package threatinsight

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/llmclient"
)

// Service provides semantic analysis operations
type Service struct {
	detector Detector
	queries  *sqlc.Queries
}

// NewService creates a new security insight service
func NewService(queries *sqlc.Queries) (*Service, error) {
	// Get LLM configuration from environment
	baseURL := os.Getenv("THREAT_INSIGHT_BASE_URL")
	if baseURL == "" {
		baseURL = os.Getenv("OPENAI_BASE_URL")
		if baseURL == "" {
			return nil, fmt.Errorf("THREAT_INSIGHT_BASE_URL or OPENAI_BASE_URL environment variable required")
		}
	}

	apiKey := os.Getenv("THREAT_INSIGHT_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}

	model := os.Getenv("THREAT_INSIGHT_MODEL")
	if model == "" {
		model = "gpt-4o"
	}

	timeout := 120 * time.Second
	if timeoutEnv := os.Getenv("THREAT_INSIGHT_TIMEOUT"); timeoutEnv != "" {
		if d, err := time.ParseDuration(timeoutEnv); err == nil {
			timeout = d
		}
	}

	// Create components
	client := llmclient.NewClient(baseURL, apiKey, timeout)
	detector := NewDetector(queries, client, model)

	log.Printf("Security insight service initialized with model: %s", model)

	return &Service{
		detector: detector,
		queries:  queries,
	}, nil
}

// AnalyzeRootExecID performs semantic analysis on a specific root_exec_id
func (s *Service) AnalyzeRootExecID(ctx context.Context, rootExecID string) (*AnalysisResult, error) {
	result, err := s.detector.Analyze(ctx, rootExecID)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	// Save analysis result to database
	if err := SaveAnalysisResult(ctx, s.queries, rootExecID, result); err != nil {
		log.Printf("Warning: Failed to save analysis result: %v", err)
	}

	return result, nil
}

// Ready checks if the service is ready (implements health check interface)
func (s *Service) Ready(ctx context.Context) error {
	// Could ping the LLM client here if needed
	return nil
}

// SaveAnalysisResult saves an analysis result to the database
func SaveAnalysisResult(ctx context.Context, queries *sqlc.Queries, rootExecID string, result *AnalysisResult) error {
	rootExecIDText := pgtype.Text{String: rootExecID, Valid: true}

	// Get host from first event
	events, err := queries.GetEventsByRootExecID(ctx, sqlc.GetEventsByRootExecIDParams{
		RootExecID: rootExecIDText,
		TidInt:     pgtype.Int4{},
		MethodText: pgtype.Text{},
		UrlText:    pgtype.Text{},
	})
	if err != nil {
		return fmt.Errorf("failed to get events for host lookup: %w", err)
	}
	if len(events) == 0 {
		return fmt.Errorf("no events found for root_exec_id: %s", rootExecID)
	}

	host := events[0].Host

	// Save analysis result using sqlc
	recommendationsJSON, _ := json.Marshal(result.Recommendations)
	evidenceJSON, _ := json.Marshal(result.Evidence)

	err = queries.InsertSecurityAnalysisResult(ctx, sqlc.InsertSecurityAnalysisResultParams{
		Host:            pgtype.Text{String: host, Valid: true},
		RootExecID:      rootExecIDText,
		ThreatLevel:     pgtype.Int4{Int32: int32(result.ThreatLevel), Valid: true},
		ThreatType:      pgtype.Text{String: result.ThreatType, Valid: true},
		Confidence:      pgtype.Float8{Float64: result.Confidence, Valid: true},
		Summary:         pgtype.Text{String: result.Summary, Valid: true},
		Details:         pgtype.Text{String: result.Details, Valid: true},
		Recommendations: recommendationsJSON,
		Evidence:        evidenceJSON,
	})

	return err
}
