package promptinjection

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/tensorchord/watchu/gateway/pkg/textencoding"
)

// RenderDetectionPrompt embeds the user prompt into the guardrail template.
func RenderDetectionPrompt(userInput string) string {
	return fmt.Sprintf(DefaultDetectionTemplate, strings.TrimSpace(userInput))
}

type GuardrailEvidence struct {
	ID             string `json:"id,omitempty"`
	Type           string `json:"type,omitempty"`
	Source         string `json:"source,omitempty"`
	Severity       string `json:"severity,omitempty"`
	Quote          string `json:"quote,omitempty"`
	Interpretation string `json:"interpretation,omitempty"`
}

// GuardrailResult captures the parsed model response.
type GuardrailResult struct {
	Safety     string
	Categories []string
	Score      float64
	Reason     string
	Evidence   []GuardrailEvidence
}

// ParseGuardrailOutput extracts severity metadata from the legacy (line-based) model output.
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
		case strings.HasPrefix(lower, "reason:"):
			reason := strings.TrimSpace(trimmed[len("Reason:"):])
			if !strings.EqualFold(reason, "none") && reason != "" {
				res.Reason = reason
			}
		}
	}
	return res
}

// ParseGuardrailResponse parses the JSON response used by prompt_based mode.
// It falls back to ParseGuardrailOutput when JSON parsing fails.
func ParseGuardrailResponse(text string) GuardrailResult {
	if parsed, ok := parseGuardrailJSON(text); ok {
		return parsed
	}
	return ParseGuardrailOutput(text)
}

type guardrailJSON struct {
	Safety     string              `json:"safety"`
	Categories []string            `json:"categories"`
	Score      float64             `json:"score"`
	Reason     string              `json:"reason"`
	Evidence   []GuardrailEvidence `json:"evidence"`
}

func parseGuardrailJSON(text string) (GuardrailResult, bool) {
	clean := strings.TrimSpace(text)
	if clean == "" {
		return GuardrailResult{}, false
	}
	// Strip Markdown code fences if present.
	if strings.HasPrefix(clean, "```") {
		if idx := strings.Index(clean, "\n"); idx >= 0 {
			clean = strings.TrimSpace(clean[idx+1:])
		}
		if end := strings.LastIndex(clean, "```"); end >= 0 {
			clean = strings.TrimSpace(clean[:end])
		}
	}
	// Attempt to extract the first JSON object if the model included extra text.
	start := strings.Index(clean, "{")
	end := strings.LastIndex(clean, "}")
	if start < 0 || end < 0 || end <= start {
		return GuardrailResult{}, false
	}
	clean = clean[start : end+1]

	var payload guardrailJSON
	if err := json.Unmarshal([]byte(clean), &payload); err != nil {
		return GuardrailResult{}, false
	}

	res := GuardrailResult{
		Safety:     strings.TrimSpace(payload.Safety),
		Categories: payload.Categories,
		Score:      payload.Score,
		Reason:     strings.TrimSpace(payload.Reason),
		Evidence:   payload.Evidence,
	}
	if len(res.Categories) == 0 && strings.EqualFold(res.Safety, "safe") {
		res.Categories = nil
	}
	return res, res.Safety != "" || res.Score > 0 || res.Reason != "" || len(res.Categories) > 0 || len(res.Evidence) > 0
}

// extractPromptText renders the stored prompt JSON (or raw request) into plain text.
func extractPromptText(promptJSON []byte, fallback string, maxLen int, stripToolCalls bool, extractUserPrompt bool) (string, bool, string) {
	if len(promptJSON) > 0 {
		if rendered, err := flattenPromptJSON(promptJSON, stripToolCalls); err == nil && rendered != "" {
			rendered = textencoding.RepairUTF8Mojibake(rendered)
			trimmed, truncated := truncateString(rendered, maxLen)
			return trimmed, truncated, "prompt_json"
		}
	}

	// Try to extract from raw HTTP request body (for direct API calls)
	if fallback != "" {
		if extracted := extractPromptFromHTTPBody(fallback, extractUserPrompt); extracted != "" {
			extracted = textencoding.RepairUTF8Mojibake(extracted)
			trimmed, truncated := truncateString(extracted, maxLen)
			return trimmed, truncated, "http_body"
		}
	}

	fallback = textencoding.RepairUTF8Mojibake(fallback)
	trimmed, truncated := truncateString(fallback, maxLen)
	source := "raw_request"
	if fallback == "" {
		source = "unknown"
	}
	return trimmed, truncated, source
}

// ExtractPromptFromHTTPBody attempts to extract prompt text from various LLM API request formats
// If extractUserPrompt is true, intelligently extracts user input from agent framework wrappers
// If extractUserPrompt is false, returns the full prompt content without extraction
// This function is exported for use in standalone tools
func ExtractPromptFromHTTPBody(body string, extractUserPrompt bool) string {
	return extractPromptFromHTTPBody(body, extractUserPrompt)
}

// extractPromptFromHTTPBody is the internal implementation
func extractPromptFromHTTPBody(body string, extractUserPrompt bool) string {
	var data map[string]any
	if err := unmarshalJSONLoose(body, &data); err != nil {
		return ""
	}

	// Try to extract from common LLM API formats

	// 1. OpenAI/Anthropic format: messages array
	if messages, ok := data["messages"].([]any); ok && len(messages) > 0 {
		var texts []string
		for _, msg := range messages {
			if msgObj, ok := msg.(map[string]any); ok {
				// Extract role and content
				role := ""
				if r, ok := msgObj["role"].(string); ok {
					role = r
				}

				// Skip assistant messages (system prompts)
				if role == "assistant" {
					continue
				}

				// Only process user messages
				if role != "user" {
					continue
				}

				content := extractMessageContent(msgObj["content"])
				if content != "" {
					// Try to extract real user input from wrapped content if enabled
					if extractUserPrompt {
						if extracted := extractUserInputFromWrappedContent(content); extracted != "" {
							content = extracted
						}
					}

					content = textencoding.RepairUTF8Mojibake(content)
					if content != "" {
						texts = append(texts, content)
					}
				}
			}
		}
		if len(texts) > 0 {
			// If extractUserPrompt is true, return the last user message (usually the actual query)
			// If false, return all user messages concatenated (full conversation)
			if extractUserPrompt {
				return texts[len(texts)-1]
			}
			return strings.Join(texts, "\n\n")
		}
	}

	// 2. Simple prompt field (some APIs)
	if prompt, ok := data["prompt"].(string); ok && prompt != "" {
		// Try to extract real user input from wrapped prompt if enabled
		if extractUserPrompt {
			if extracted := extractUserInputFromWrappedContent(prompt); extracted != "" {
				return textencoding.RepairUTF8Mojibake(extracted)
			}
		}
		return textencoding.RepairUTF8Mojibake(prompt)
	}

	// 3. Google Gemini format: contents array
	if contents, ok := data["contents"].([]any); ok && len(contents) > 0 {
		var userTexts []string
		for _, content := range contents {
			if contentObj, ok := content.(map[string]any); ok {
				// Check if this is a user role message
				role := ""
				if r, ok := contentObj["role"].(string); ok {
					role = r
				}

				// Only extract from user messages
				if role != "user" {
					continue
				}

				if parts, ok := contentObj["parts"].([]any); ok {
					for _, part := range parts {
						if partObj, ok := part.(map[string]any); ok {
							if text, ok := partObj["text"].(string); ok && text != "" {
								// Clean system tags if extraction is enabled
								if extractUserPrompt {
									text = cleanSystemTags(text)

									// Skip Gemini setup messages
									if isGeminiSetupMessage(text) {
										continue
									}

									// Try to extract real user input from wrapped text
									if extracted := extractUserInputFromWrappedContent(text); extracted != "" {
										text = extracted
									}
								}

								if text != "" {
									text = textencoding.RepairUTF8Mojibake(text)
									userTexts = append(userTexts, text)
								}
							}
						}
					}
				}
			}
		}
		if len(userTexts) > 0 {
			// If extractUserPrompt is true, return the last user text (usually the actual query)
			// If false, return all user texts concatenated (full context)
			if extractUserPrompt {
				return userTexts[len(userTexts)-1]
			}
			return strings.Join(userTexts, "\n\n")
		}
	}

	return ""
}

func unmarshalJSONLoose(input string, out any) error {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return fmt.Errorf("empty input")
	}
	if err := json.Unmarshal([]byte(raw), out); err == nil {
		return nil
	}

	// Some payloads might contain extra prefix/suffix; try extracting the first JSON object.
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(raw[start:end+1]), out); err == nil {
			return nil
		}
	}

	// Last resort: interpret the bytes as ISO-8859-1 (LATIN1) and retry.
	latin1 := decodeLatin1ToUTF8(raw)
	if err := json.Unmarshal([]byte(latin1), out); err == nil {
		return nil
	}
	start = strings.Index(latin1, "{")
	end = strings.LastIndex(latin1, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(latin1[start:end+1]), out); err == nil {
			return nil
		}
	}

	return fmt.Errorf("unable to parse JSON")
}

func decodeLatin1ToUTF8(input string) string {
	if input == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(input))
	for i := 0; i < len(input); i++ {
		b.WriteRune(rune(input[i]))
	}
	return b.String()
}

// cleanSystemTags removes XML-style system tags from content
func cleanSystemTags(content string) string {
	// Remove <system-reminder>...</system-reminder> blocks
	lines := strings.Split(content, "\n")
	var filtered []string
	inSystemBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect system block start (any <system-* tag)
		if strings.HasPrefix(trimmed, "<system-") {
			inSystemBlock = true
			continue
		}

		// Detect system block end (any </system-* tag)
		if strings.HasPrefix(trimmed, "</system-") {
			inSystemBlock = false
			continue
		}

		// Skip lines in system block or empty lines at boundaries
		if inSystemBlock {
			continue
		}

		// Keep non-system lines (but skip if it's just whitespace)
		if trimmed != "" || len(filtered) > 0 {
			filtered = append(filtered, line)
		}
	}

	// Join and clean up extra whitespace
	result := strings.Join(filtered, "\n")
	result = strings.TrimSpace(result)

	// Remove multiple consecutive newlines
	for strings.Contains(result, "\n\n\n") {
		result = strings.ReplaceAll(result, "\n\n\n", "\n\n")
	}

	return result
}

// isGeminiSetupMessage detects if a text is a Gemini CLI setup message
func isGeminiSetupMessage(text string) bool {
	setupMarkers := []string{
		"This is the Gemini CLI",
		"We are setting up the context",
		"My setup is complete",
		"Here is the user's editor context",
		"Reminder: Do not return an empty response",
	}

	for _, marker := range setupMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}

	return false
}

// extractUserInputFromWrappedContent tries to extract the real user input from wrapped content
// Common patterns in agent frameworks:
// - "USER_INPUT: <actual input>"
// - "[user] <actual input>" after long assistant instructions
// - "Human: <actual input>" / "User: <actual input>"
func extractUserInputFromWrappedContent(content string) string {
	if content == "" {
		return ""
	}

	// Pattern 1: USER_INPUT: marker (used in security classifiers)
	if idx := strings.Index(content, "USER_INPUT:"); idx >= 0 {
		afterMarker := content[idx+len("USER_INPUT:"):]
		extracted := strings.TrimSpace(afterMarker)
		if extracted != "" {
			// Check if there's a [user] marker within the USER_INPUT content
			if userExtracted := extractLastUserMessage(extracted); userExtracted != "" {
				return userExtracted
			}
			return extracted
		}
	}

	// Pattern 2: [user] marker after [assistant] instructions
	// This handles cases like: "[assistant] <long instructions> [user] <actual prompt>"
	if extracted := extractLastUserMessage(content); extracted != "" {
		return extracted
	}

	// Pattern 3: Human:/User: markers (Anthropic style)
	for _, marker := range []string{"Human:", "User:", "human:", "user:"} {
		if idx := strings.LastIndex(content, marker); idx >= 0 {
			afterMarker := content[idx+len(marker):]
			// Extract until next role marker or end
			for _, endMarker := range []string{"\nAssistant:", "\nassistant:", "\nAI:", "\nai:"} {
				if endIdx := strings.Index(afterMarker, endMarker); endIdx >= 0 {
					afterMarker = afterMarker[:endIdx]
					break
				}
			}
			extracted := strings.TrimSpace(afterMarker)
			if extracted != "" && len(extracted) < int(float64(len(content))*0.8) {
				// Only return if it's significantly shorter than the full content
				return extracted
			}
		}
	}

	// Pattern 4: Check if content starts with long instructions and has a separator
	// Look for common separators like "---", "###", or empty lines followed by actual content
	if len(content) > 500 {
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Look for separator patterns
			if trimmed == "---" || trimmed == "###" || (trimmed == "" && i > 0 && i < len(lines)-1) {
				// Check if there's substantial content after the separator
				remaining := strings.Join(lines[i+1:], "\n")
				remaining = strings.TrimSpace(remaining)
				if remaining != "" && len(remaining) < int(float64(len(content))*0.5) {
					return remaining
				}
			}
		}
	}

	// No pattern matched, return empty to indicate no extraction
	return ""
}

// extractLastUserMessage extracts the last [user] message from content
// This handles cases like: "[assistant] <long instructions> [user] <actual prompt>"
func extractLastUserMessage(content string) string {
	if !strings.Contains(content, "[user]") {
		return ""
	}

	// Find the last [user] marker which is likely the real user input
	parts := strings.Split(content, "[user]")
	if len(parts) <= 1 {
		return ""
	}

	lastUserPart := strings.TrimSpace(parts[len(parts)-1])

	// Also check if there's a [tool] marker after, and extract up to that point
	if toolIdx := strings.Index(lastUserPart, "[tool]"); toolIdx >= 0 {
		lastUserPart = strings.TrimSpace(lastUserPart[:toolIdx])
	}

	// Also check for [assistant] marker after (in case of multi-turn)
	if assistIdx := strings.Index(lastUserPart, "[assistant]"); assistIdx >= 0 {
		lastUserPart = strings.TrimSpace(lastUserPart[:assistIdx])
	}

	if lastUserPart != "" {
		return lastUserPart
	}

	return ""
}

// extractMessageContent extracts text from message content (handles both string and array formats)
func extractMessageContent(content any) string {
	if content == nil {
		return ""
	}

	// String format
	if s, ok := content.(string); ok {
		return s
	}

	// Array format (Anthropic/Claude style)
	if arr, ok := content.([]any); ok {
		var texts []string
		for _, item := range arr {
			if obj, ok := item.(map[string]any); ok {
				if typ, _ := obj["type"].(string); typ == "text" {
					if text, ok := obj["text"].(string); ok && text != "" {
						// Clean system tags from each text part
						cleaned := cleanSystemTags(text)
						if cleaned != "" {
							texts = append(texts, cleaned)
						}
					}
				}
			}
		}
		result := strings.Join(texts, "\n")
		return strings.TrimSpace(result)
	}

	return ""
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
		for i := range texts {
			texts[i] = textencoding.RepairUTF8Mojibake(texts[i])
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
		return []string{textencoding.RepairUTF8Mojibake(txt)}
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
				texts = append(texts, textencoding.RepairUTF8Mojibake(txt))
				continue
			}
			if nested := extractArray(item["parts"]); len(nested) > 0 {
				texts = append(texts, collectTextParts(nested, stripToolCalls)...)
			}
		case string:
			if item != "" {
				texts = append(texts, textencoding.RepairUTF8Mojibake(item))
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
