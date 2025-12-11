package promptinjection

import (
	"context"
	"fmt"
)

// LLMBasedStrategy uses an LLM to detect prompt injection
type LLMBasedStrategy struct {
	client   *Client
	model    string
	template string
}

// NewLLMBasedStrategy creates a new LLM-based detection strategy
func NewLLMBasedStrategy(client *Client, model string, template string) *LLMBasedStrategy {
	if template == "" {
		template = DefaultDetectionTemplate
	}
	return &LLMBasedStrategy{
		client:   client,
		model:    model,
		template: template,
	}
}

func (s *LLMBasedStrategy) Name() string {
	return "llm_based"
}

func (s *LLMBasedStrategy) ShouldExtractUserPrompt() bool {
	return true // LLM-based detection works best with extracted user prompts
}

func (s *LLMBasedStrategy) Detect(prompt string) (GuardrailResult, error) {
	var detectionPrompt string

	// If template is empty, use model_based mode (direct prompt)
	if s.template == "" {
		detectionPrompt = prompt
	} else {
		// Use template (prompt_based mode)
		detectionPrompt = fmt.Sprintf(s.template, prompt)
	}

	ctx := context.Background()
	completion, err := s.client.Detect(ctx, s.model, detectionPrompt)
	if err != nil {
		return GuardrailResult{}, fmt.Errorf("llm detection failed: %w", err)
	}

	return ParseGuardrailOutput(completion), nil
}
