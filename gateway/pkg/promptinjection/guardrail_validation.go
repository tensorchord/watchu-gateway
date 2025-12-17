package promptinjection

import (
	"fmt"
	"strings"
)

func validateGuardrailEvidence(items []GuardrailEvidence, input string) []GuardrailEvidence {
	if len(items) == 0 {
		return nil
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	out := make([]GuardrailEvidence, 0, len(items))
	for i, it := range items {
		quote := strings.TrimSpace(it.Quote)
		if quote == "" {
			continue
		}
		if !strings.Contains(input, quote) {
			continue
		}
		it.Quote = quote
		it.Type = strings.TrimSpace(it.Type)
		it.Source = strings.TrimSpace(it.Source)
		it.Severity = strings.TrimSpace(it.Severity)
		it.Interpretation = strings.TrimSpace(it.Interpretation)
		if strings.TrimSpace(it.ID) == "" {
			it.ID = fmt.Sprintf("e%d", i+1)
		}
		out = append(out, it)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
