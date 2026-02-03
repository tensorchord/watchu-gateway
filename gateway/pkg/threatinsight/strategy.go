package threatinsight

import (
	"context"
)

// AnalysisStrategy defines the interface for semantic analysis strategies
type AnalysisStrategy interface {
	// Analyze performs threat analysis using root_exec_id (legacy method, may include events from multiple analyses)
	Analyze(ctx context.Context, rootExecID string) (*AnalysisResult, error)
	// AnalyzeByCorrelationID performs threat analysis using correlation_id (analysis_id) for precise per-analysis isolation
	// analysisType indicates the type of analysis (e.g., "skill_security_saas") for context-aware threat detection
	AnalyzeByCorrelationID(ctx context.Context, correlationID string, skillName string, analysisType string) (*AnalysisResult, error)
}
