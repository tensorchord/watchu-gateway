package promptinjection

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const detectionTemplate = `You are a security content classifier. Inspect the USER_INPUT and answer using this exact format:

Safety: <Safe|Controversial|Unsafe>
Categories: <comma-separated categories or None>
Score: <0.00-1.00>

Safety levels:
- Safe: content generally considered safe in most scenarios.
- Controversial: content whose harmfulness depends on context.
- Unsafe: content generally considered harmful.

Valid categories:
- Violent
- Non-violent Illegal Acts
- Sexual Content or Sexual Acts
- Personally Identifiable Information
- Suicide & Self-Harm
- Unethical Acts
- Politically Sensitive Topics
- Copyright Violation
- Jailbreak
- None

USER_INPUT: %s`

// RenderDetectionPrompt embeds the user prompt into the guardrail template.
func RenderDetectionPrompt(userInput string) string {
	return fmt.Sprintf(detectionTemplate, strings.TrimSpace(userInput))
}

// GuardrailResult captures the parsed model response.
type GuardrailResult struct {
	Safety     string
	Categories []string
	Score      float64
}

// ParseGuardrailOutput extracts severity metadata from the model output.
func ParseGuardrailOutput(text string) GuardrailResult {
	res := GuardrailResult{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "safety:"):
			res.Safety = strings.TrimSpace(trimmed[len("Safety:"):])
		case strings.HasPrefix(lower, "categories:"):
			raw := strings.Split(trimmed[len("Categories:"):], ",")
			var cats []string
			for _, c := range raw {
				clean := strings.TrimSpace(c)
				if clean == "" || strings.EqualFold(clean, "none") {
					continue
				}
				cats = append(cats, clean)
			}
			res.Categories = cats
		case strings.HasPrefix(lower, "score:"):
			value := strings.TrimSpace(trimmed[len("Score:"):])
			if parsed, err := strconv.ParseFloat(value, 64); err == nil {
				res.Score = parsed
			}
		}
	}
	return res
}

// extractPromptText renders the stored prompt JSON (or raw request) into plain text.
func extractPromptText(promptJSON []byte, fallback string, maxLen int, stripToolCalls bool) (string, bool, string) {
	if len(promptJSON) > 0 {
		if rendered, err := flattenPromptJSON(promptJSON, stripToolCalls); err == nil && rendered != "" {
			trimmed, truncated := truncateString(rendered, maxLen)
			return trimmed, truncated, "prompt_json"
		}
	}
	trimmed, truncated := truncateString(fallback, maxLen)
	source := "raw_request"
	if fallback == "" {
		source = "unknown"
	}
	return trimmed, truncated, source
}

func flattenPromptJSON(raw []byte, stripToolCalls bool) (string, error) {
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", err
	}
	entries, ok := data.([]any)
	if !ok {
		return "", fmt.Errorf("prompt json is not an array")
	}
	var builder strings.Builder
	for _, entry := range entries {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		texts := collectMessageTexts(obj, stripToolCalls)
		if len(texts) == 0 {
			continue
		}
		role := fmt.Sprint(obj["role"])
		if role != "" {
			builder.WriteString("[")
			builder.WriteString(role)
			builder.WriteString("] ")
		}
		builder.WriteString(strings.Join(texts, "\n"))
		builder.WriteString("\n\n")
	}
	return strings.TrimSpace(builder.String()), nil
}

func collectMessageTexts(obj map[string]any, stripToolCalls bool) []string {
	if parts := extractArray(obj["parts"]); len(parts) > 0 {
		return collectTextParts(parts, stripToolCalls)
	}
	if content := extractArray(obj["content"]); len(content) > 0 {
		return collectTextParts(content, stripToolCalls)
	}
	if txt, ok := obj["text"].(string); ok && txt != "" {
		return []string{txt}
	}
	return nil
}

func collectTextParts(parts []any, stripToolCalls bool) []string {
	texts := make([]string, 0, len(parts))
	for _, part := range parts {
		switch item := part.(type) {
		case map[string]any:
			if stripToolCalls && isToolPayload(item) {
				continue
			}
			if txt, ok := item["text"].(string); ok && txt != "" {
				texts = append(texts, txt)
				continue
			}
			if nested := extractArray(item["parts"]); len(nested) > 0 {
				texts = append(texts, collectTextParts(nested, stripToolCalls)...)
			}
		case string:
			if item != "" {
				texts = append(texts, item)
			}
		}
	}
	return texts
}

func extractArray(value any) []any {
	if arr, ok := value.([]any); ok {
		return arr
	}
	return nil
}

func isToolPayload(obj map[string]any) bool {
	if _, ok := obj["functionCall"]; ok {
		return true
	}
	if _, ok := obj["function_call"]; ok {
		return true
	}
	if _, ok := obj["toolCall"]; ok {
		return true
	}
	if _, ok := obj["tool_call"]; ok {
		return true
	}
	if typ, ok := obj["type"].(string); ok {
		lower := strings.ToLower(typ)
		if strings.Contains(lower, "tool") {
			return true
		}
	}
	if nested := extractArray(obj["content"]); len(nested) > 0 {
		for _, entry := range nested {
			if child, ok := entry.(map[string]any); ok && isToolPayload(child) {
				return true
			}
		}
	}
	return false
}

func truncateString(value string, max int) (string, bool) {
	if max <= 0 || len(value) <= max {
		return value, false
	}
	runes := []rune(value)
	if len(runes) <= max {
		return value, false
	}
	return string(runes[:max]), true
}
