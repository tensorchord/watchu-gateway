package threatinsight

import (
	"context"
)

// AnalysisStrategy defines the interface for semantic analysis strategies
type AnalysisStrategy interface {
	Analyze(ctx context.Context, rootExecID string) (*AnalysisResult, error)
}
