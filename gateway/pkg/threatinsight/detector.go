package threatinsight

import (
	"context"

	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/llmclient"
)

// AnalysisResult represents the structured output of semantic analysis
type AnalysisResult struct {
	ThreatLevel     int                      `json:"threat_level"`    // 1-5 scale (1=benign, 5=critical)
	ThreatType      string                   `json:"threat_type"`     // prompt_injection, reasoning_loop, data_exfiltration, resource_abuse, coordination_failure, none, other
	Confidence      float64                  `json:"confidence"`      // 0.0-1.0
	Summary         string                   `json:"summary"`         // 1-3 sentence summary
	Details         string                   `json:"details"`         // detailed analysis
	Recommendations []string                 `json:"recommendations"` // remediation actions
	Evidence        []map[string]interface{} `json:"evidence"`        // evidence entries
}

// Detector is the core interface for semantic security analysis
type Detector interface {
	// Analyze performs semantic analysis on telemetry data and returns structured results
	Analyze(ctx context.Context, rootExecID string) (*AnalysisResult, error)
}

// detectorImpl implements the Detector interface
type detectorImpl struct {
	strategy AnalysisStrategy
}

// NewDetector creates a detector using the specified sqlc queries and LLM client
func NewDetector(queries *sqlc.Queries, client *llmclient.Client, model string) Detector {
	strategy := NewLLMBasedStrategy(queries, client, model)
	return &detectorImpl{
		strategy: strategy,
	}
}

// Analyze implements the Detector interface
func (d *detectorImpl) Analyze(ctx context.Context, rootExecID string) (*AnalysisResult, error) {
	return d.strategy.Analyze(ctx, rootExecID)
}
