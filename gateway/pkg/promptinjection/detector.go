package promptinjection

import (
	"context"
	"fmt"
)

// Detector is the core interface for prompt injection detection
type Detector interface {
	// Detect analyzes the given prompt and returns a detection result
	Detect(ctx context.Context, prompt string) (GuardrailResult, error)
}

// detectorImpl implements the Detector interface
type detectorImpl struct {
	strategy DetectionStrategy
}

// NewDetector creates a detector based on the specified mode
func NewDetector(client *Client, model string, mode string) Detector {
	var strategy DetectionStrategy

	switch mode {
	case "model_based":
		// model_based: no template, direct prompt to model
		strategy = NewLLMBasedStrategy(client, model, "")
	case "prompt_based":
		// prompt_based: use detection template
		strategy = NewLLMBasedStrategy(client, model, DefaultDetectionTemplate)
	default:
		// Default to prompt_based
		strategy = NewLLMBasedStrategy(client, model, DefaultDetectionTemplate)
	}

	return &detectorImpl{
		strategy: strategy,
	}
}

// Detect implements the Detector interface
func (d *detectorImpl) Detect(ctx context.Context, prompt string) (GuardrailResult, error) {
	return d.strategy.Detect(prompt)
}

// Ping checks if the detector is ready (for health checks)
func (d *detectorImpl) Ping(ctx context.Context) error {
	// Try to get the underlying client if available
	if llmStrategy, ok := d.strategy.(*LLMBasedStrategy); ok {
		return llmStrategy.client.Ping(ctx)
	}
	return fmt.Errorf("strategy does not support ping")
}

// formatGuardrailResult converts GuardrailResult to a formatted string
func formatGuardrailResult(result GuardrailResult) string {
	return fmt.Sprintf("Safety: %s, Categories: %v, Score: %.2f, Reason: %s",
		result.Safety, result.Categories, result.Score, result.Reason)
}
