package threatinsight

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
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

	// Save analysis result to database without linking to a specific skill_analysis
	// (for backward compatibility with direct threat analysis calls)
	if err := SaveAnalysisResult(ctx, s.queries, rootExecID, pgtype.UUID{}, result); err != nil {
		log.Printf("Warning: Failed to save analysis result: %v", err)
	}

	return result, nil
}

// Ready checks if the service is ready (implements health check interface)
func (s *Service) Ready(ctx context.Context) error {
	// Could ping the LLM client here if needed
	return nil
}

// SaveAnalysisResult saves an analysis result to the unified security_events table
// If analysisID is provided, it links the threat result to a specific skill_analysis
func SaveAnalysisResult(ctx context.Context, queries *sqlc.Queries, rootExecID string, analysisID pgtype.UUID, result *AnalysisResult) error {
	// analysisID is required for security_events table
	if !analysisID.Valid {
		return fmt.Errorf("analysisID is required for saving to security_events table")
	}

	// Map threat level (1-5) to severity
	severity := threatLevelToSeverity(result.ThreatLevel)

	// Convert result to security event format
	recommendationsJSON, _ := json.Marshal(result.Recommendations)
	evidenceJSON, _ := json.Marshal(result.Evidence)

	// Build telemetry summary with context
	status := strings.TrimSpace(result.Status)
	if status == "" {
		status = "ready"
	}
	telemetrySummary := map[string]interface{}{
		"threat_level": result.ThreatLevel,
		"threat_type":  result.ThreatType,
		"confidence":   result.Confidence,
		"root_exec_id": rootExecID,
		"analysis_status": status,
	}
	telemetryJSON, _ := json.Marshal(telemetrySummary)

	// Use UpsertSecurityEvent to save or update dynamic analysis result
	confidenceNum := pgtype.Numeric{}
	_ = confidenceNum.Scan(result.Confidence)

	_, err := queries.UpsertSecurityEvent(ctx, sqlc.UpsertSecurityEventParams{
		AnalysisID:         analysisID,
		SourceType:         "dynamic",
		Severity:           severity,
		Category:           pgtype.Text{String: result.ThreatType, Valid: true},
		Title:              result.Summary,
		Description:        pgtype.Text{String: result.Details, Valid: true},
		Confidence:         confidenceNum,
		CodeSnippet:        pgtype.Text{},
		FilePath:           pgtype.Text{},
		ReferenceLinks:     []byte("[]"),
		TelemetrySummary:   telemetryJSON,
		ThreatAnalysisStatus: pgtype.Text{String: status, Valid: true},
		AiGeneratedSummary: pgtype.Text{},
		Recommendations:    recommendationsJSON,
		Evidence:           evidenceJSON,
		Metadata:           []byte("{}"),
	})

	return err
}

// threatLevelToSeverity maps threat level (1-5) to severity string
func threatLevelToSeverity(level int) string {
	switch level {
	case 5:
		return "critical"
	case 4:
		return "high"
	case 3:
		return "medium"
	case 2:
		return "low"
	case 1:
		return "info"
	default:
		return "none"
	}
}
