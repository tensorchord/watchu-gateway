package promptinjection

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

type ObservedEvidence struct {
	EvidenceVerbosity string              `json:"evidence_verbosity,omitempty"`
	Calls             []ObservedCall      `json:"calls,omitempty"`
	Indicators        []ObservedIndicator `json:"indicators,omitempty"`
	Notes             []string            `json:"notes,omitempty"`
}

type ObservedCall struct {
	ToolName   string            `json:"tool_name,omitempty"`
	Arguments  string            `json:"arguments,omitempty"`
	Snippets   []ObservedSnippet `json:"snippets,omitempty"`
	ResultHint string            `json:"result_hint,omitempty"`
}

type ObservedSnippet struct {
	Type    string `json:"type,omitempty"`    // sql|shell|python|http|filesystem|other
	Content string `json:"content,omitempty"` // redacted + length-capped
}

type ObservedIndicator struct {
	Kind   string `json:"kind,omitempty"`   // credential|pii|exfiltration|jailbreak|destructive|other
	Source string `json:"source,omitempty"` // user_input|tool_args|tool_result|raw_request
	Match  string `json:"match,omitempty"`  // redacted + length-capped
}

func buildObservedEvidence(rawRequest string, verbosity string, maxChars int) ObservedEvidence {
	verbosity = strings.ToLower(strings.TrimSpace(verbosity))
	if verbosity == "" {
		verbosity = "standard"
	}
	maxChars = maxEvidenceChars(verbosity, maxChars)

	ev := ObservedEvidence{
		EvidenceVerbosity: verbosity,
	}
	if strings.TrimSpace(rawRequest) == "" {
		ev.Notes = append(ev.Notes, "raw_request unavailable")
		return ev
	}

	var data map[string]any
	if err := unmarshalJSONLoose(rawRequest, &data); err != nil {
		ev.Notes = append(ev.Notes, "raw_request is not valid JSON")
		return ev
	}

	// OpenAI-compatible: messages array
	if messages, ok := data["messages"].([]any); ok && len(messages) > 0 {
		for _, msg := range messages {
			msgObj, ok := msg.(map[string]any)
			if !ok {
				continue
			}
			role, _ := msgObj["role"].(string)

			// Tool calls usually appear on assistant role messages.
			if toolCalls := extractArray(msgObj["tool_calls"]); len(toolCalls) > 0 {
				ev.Calls = append(ev.Calls, extractToolCalls(toolCalls, maxChars)...)
			}
			if funcCall, ok := msgObj["function_call"].(map[string]any); ok && len(funcCall) > 0 {
				ev.Calls = append(ev.Calls, extractFunctionCall(funcCall, maxChars))
			}

			// Tool results often appear as role=tool content.
			if role == "tool" {
				content := extractMessageContent(msgObj["content"])
				content = capAndRedact(content, maxChars)
				if content != "" {
					hints := inferIndicators("tool_result", content, maxChars)
					ev.Indicators = append(ev.Indicators, hints...)
					ev.Calls = append(ev.Calls, ObservedCall{
						ToolName:   "tool_result",
						Arguments:  "",
						Snippets:   extractSnippets(content, maxChars),
						ResultHint: capAndRedact(summarizeToolResult(content), maxChars),
					})
				}
			}
		}
	}

	// Gemini: contents array (may include model functionCall and user functionResponse parts)
	if contents, ok := data["contents"].([]any); ok && len(contents) > 0 {
		ev.Calls = append(ev.Calls, extractGeminiContents(contents, maxChars)...)
	}

	// Fall back to prompt field for non-messages APIs.
	if len(ev.Calls) == 0 {
		if prompt, ok := data["prompt"].(string); ok && prompt != "" {
			prompt = capAndRedact(prompt, maxChars)
			ev.Calls = append(ev.Calls, ObservedCall{
				ToolName:  "prompt",
				Arguments: prompt,
				Snippets:  extractSnippets(prompt, maxChars),
			})
			ev.Indicators = append(ev.Indicators, inferIndicators("raw_request", prompt, maxChars)...)
		}
	}

	// Indicators: scan call arguments and tool results (avoid scanning entire setup/system blocks).
	for _, call := range ev.Calls {
		if call.Arguments != "" {
			ev.Indicators = append(ev.Indicators, inferIndicators("tool_args", call.Arguments, maxChars)...)
		}
		if call.ResultHint != "" {
			ev.Indicators = append(ev.Indicators, inferIndicators("tool_result", call.ResultHint, maxChars)...)
		}
		for _, snip := range call.Snippets {
			if snip.Content != "" {
				ev.Indicators = append(ev.Indicators, inferIndicators("tool_args", snip.Content, maxChars)...)
			}
		}
	}

	ev.Indicators = dedupeIndicators(ev.Indicators)
	return ev
}

func extractGeminiContents(contents []any, maxChars int) []ObservedCall {
	var out []ObservedCall
	for _, entry := range contents {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		role, _ := obj["role"].(string)
		parts := extractArray(obj["parts"])
		if len(parts) == 0 {
			continue
		}
		for _, part := range parts {
			partObj, ok := part.(map[string]any)
			if !ok {
				continue
			}

			// Tool call
			if fc, ok := partObj["functionCall"].(map[string]any); ok {
				name, _ := fc["name"].(string)
				argsObj := fc["args"]
				argsRaw := ""
				if argsObj != nil {
					if b, err := json.Marshal(argsObj); err == nil {
						argsRaw = string(b)
					}
				}
				redactedArgs := capAndRedact(argsRaw, maxChars)
				call := ObservedCall{
					ToolName:  strings.TrimSpace(name),
					Arguments: redactedArgs,
					Snippets:  extractSnippetsFromJSONArgs(argsRaw, maxChars),
				}
				call.Snippets = dedupeSnippets(call.Snippets)
				out = append(out, call)
				continue
			}

			// Tool response (Gemini wraps functionResponse inside a user role content)
			if fr, ok := partObj["functionResponse"].(map[string]any); ok {
				name, _ := fr["name"].(string)
				respObj := fr["response"]
				respRaw := ""
				if respObj != nil {
					if b, err := json.Marshal(respObj); err == nil {
						respRaw = string(b)
					}
				}
				redacted := capAndRedact(respRaw, maxChars)
				call := ObservedCall{
					ToolName:   strings.TrimSpace(name),
					ResultHint: redacted,
				}
				// Try to pull likely output strings for snippet extraction.
				if output := extractLikelyOutput(respObj); output != "" {
					call.Snippets = append(call.Snippets, extractSnippets(capAndRedact(output, maxChars), maxChars)...)
				}
				call.Snippets = dedupeSnippets(call.Snippets)
				out = append(out, call)
				continue
			}

			// Plain text parts can still contain executable snippets (less common for Gemini tool calling).
			if role != "" {
				if text, ok := partObj["text"].(string); ok && strings.TrimSpace(text) != "" {
					text = capAndRedact(text, maxChars)
					snips := extractSnippets(text, maxChars)
					if len(snips) > 0 {
						out = append(out, ObservedCall{
							ToolName:  "text",
							Arguments: text,
							Snippets:  snips,
						})
					}
				}
			}
		}
	}
	return out
}

func extractLikelyOutput(value any) string {
	obj, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	if out, ok := obj["output"].(string); ok && strings.TrimSpace(out) != "" {
		return out
	}
	// Some tools might use "stdout" or "content".
	if out, ok := obj["stdout"].(string); ok && strings.TrimSpace(out) != "" {
		return out
	}
	if out, ok := obj["content"].(string); ok && strings.TrimSpace(out) != "" {
		return out
	}
	return ""
}

func extractToolCalls(toolCalls []any, maxChars int) []ObservedCall {
	out := make([]ObservedCall, 0, len(toolCalls))
	for _, item := range toolCalls {
		tc, ok := item.(map[string]any)
		if !ok {
			continue
		}
		toolName := ""
		argsRaw := ""

		if fn, ok := tc["function"].(map[string]any); ok {
			toolName, _ = fn["name"].(string)
			argsRaw, _ = fn["arguments"].(string)
		}
		if toolName == "" {
			toolName, _ = tc["name"].(string)
		}
		if argsRaw == "" {
			// Some agents store arguments as structured object.
			if argsObj, ok := tc["arguments"]; ok {
				if b, err := json.Marshal(argsObj); err == nil {
					argsRaw = string(b)
				}
			}
		}

		redactedArgs := capAndRedact(argsRaw, maxChars)
		call := ObservedCall{
			ToolName:  strings.TrimSpace(toolName),
			Arguments: redactedArgs,
			Snippets:  extractSnippets(redactedArgs, maxChars),
		}
		call.Snippets = append(call.Snippets, extractSnippetsFromJSONArgs(argsRaw, maxChars)...)
		call.Snippets = dedupeSnippets(call.Snippets)
		out = append(out, call)
	}
	return out
}

func extractFunctionCall(fc map[string]any, maxChars int) ObservedCall {
	toolName, _ := fc["name"].(string)
	argsRaw, _ := fc["arguments"].(string)
	redactedArgs := capAndRedact(argsRaw, maxChars)
	call := ObservedCall{
		ToolName:  strings.TrimSpace(toolName),
		Arguments: redactedArgs,
		Snippets:  extractSnippets(redactedArgs, maxChars),
	}
	call.Snippets = append(call.Snippets, extractSnippetsFromJSONArgs(argsRaw, maxChars)...)
	call.Snippets = dedupeSnippets(call.Snippets)
	return call
}

func extractSnippetsFromJSONArgs(args string, maxChars int) []ObservedSnippet {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(args), &parsed); err != nil {
		return nil
	}

	var texts []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				lower := strings.ToLower(k)
				// Prefer keys that tend to carry executable text.
				if s, ok := vv.(string); ok && s != "" && isLikelySnippetKey(lower) {
					texts = append(texts, s)
					continue
				}
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		case string:
			// Avoid pulling every random string; snippets are handled by known keys above.
		default:
		}
	}
	walk(parsed)

	var out []ObservedSnippet
	for _, t := range texts {
		out = append(out, extractSnippets(capAndRedact(t, maxChars), maxChars)...)
	}
	return dedupeSnippets(out)
}

func isLikelySnippetKey(key string) bool {
	switch key {
	case "sql", "query", "command", "cmd", "script", "code", "statement", "program":
		return true
	default:
		return strings.Contains(key, "sql") || strings.Contains(key, "query") || strings.Contains(key, "command") || strings.Contains(key, "script")
	}
}

var fenceRE = regexp.MustCompile("(?s)```\\s*([a-zA-Z0-9_+-]*)\\s*\\n(.*?)```")

func extractSnippets(text string, maxChars int) []ObservedSnippet {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	matches := fenceRE.FindAllStringSubmatch(text, -1)
	if len(matches) > 0 {
		out := make([]ObservedSnippet, 0, len(matches))
		for _, m := range matches {
			lang := strings.ToLower(strings.TrimSpace(m[1]))
			body := strings.TrimSpace(m[2])
			if body == "" {
				continue
			}
			out = append(out, ObservedSnippet{
				Type:    normalizeSnippetType(lang, body),
				Content: capAndRedact(body, maxChars),
			})
		}
		return dedupeSnippets(out)
	}

	typ := classifySnippetType(text)
	if typ == "other" {
		return nil
	}
	return []ObservedSnippet{{
		Type:    typ,
		Content: capAndRedact(text, maxChars),
	}}
}

func classifySnippetType(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "select ") && strings.Contains(lower, " from "):
		return "sql"
	case strings.Contains(lower, "insert ") && strings.Contains(lower, " into "):
		return "sql"
	case strings.Contains(lower, "update ") && strings.Contains(lower, " set "):
		return "sql"
	case strings.Contains(lower, "delete ") && strings.Contains(lower, " from "):
		return "sql"
	case strings.Contains(lower, "#!/bin/bash") || strings.Contains(lower, "#!/usr/bin/env bash"):
		return "shell"
	case strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ") || strings.Contains(lower, "psql ") || strings.Contains(lower, "kubectl "):
		return "shell"
	case strings.Contains(lower, "import ") && strings.Contains(lower, "def "):
		return "python"
	case strings.Contains(lower, "#!/usr/bin/env python") || strings.Contains(lower, "python -c") || strings.Contains(lower, "python3 -c"):
		return "python"
	case strings.Contains(lower, "http://") || strings.Contains(lower, "https://"):
		return "http"
	case strings.Contains(lower, "/etc/") || strings.Contains(lower, "~/.") || strings.Contains(lower, "c:\\"):
		return "filesystem"
	default:
		return "other"
	}
}

func normalizeSnippetType(lang string, content string) string {
	switch lang {
	case "sql":
		return "sql"
	case "bash", "sh", "shell", "zsh":
		return "shell"
	case "python", "py":
		return "python"
	case "http":
		return "http"
	default:
		// Fall back to heuristic classification on content.
		if lang == "" || lang == "text" {
			return classifySnippetType(content)
		}
		return "other"
	}
}

func maxEvidenceChars(verbosity string, maxChars int) int {
	if maxChars <= 0 {
		maxChars = 4096
	}
	switch strings.ToLower(strings.TrimSpace(verbosity)) {
	case "full":
		return maxChars
	case "minimal":
		if maxChars > 256 {
			return 256
		}
		return maxChars
	default: // standard
		if maxChars > 1024 {
			return 1024
		}
		return maxChars
	}
}

func capAndRedact(text string, maxChars int) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	text = redactSensitive(text)
	if len(text) <= maxChars {
		return text
	}
	runes := []rune(text)
	if len(runes) <= maxChars {
		return text
	}
	return strings.TrimSpace(string(runes[:maxChars]))
}

var emailRE = regexp.MustCompile(`[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,24}`)
var bearerRE = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}\b`)
var secretKVRE = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\b\s*[:=]\s*([^\s'"]{4,}|\"[^\"]{4,}\"|'[^']{4,}')`)
var jsonSecretRE = regexp.MustCompile(`(?i)\"(password|passwd|pwd|token|secret|api[_-]?key)\"\\s*:\\s*\"[^\"]{1,}\"`)

func redactSensitive(text string) string {
	text = bearerRE.ReplaceAllString(text, "Bearer <redacted>")
	text = jsonSecretRE.ReplaceAllStringFunc(text, func(s string) string {
		// Preserve the key, redact the value.
		if idx := strings.Index(s, ":"); idx >= 0 {
			return s[:idx+1] + " \"<redacted>\""
		}
		return "\"<redacted>\""
	})
	text = secretKVRE.ReplaceAllString(text, "$1=<redacted>")
	text = emailRE.ReplaceAllStringFunc(text, maskEmail)
	return text
}

func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "<redacted_email>"
	}
	local := parts[0]
	domain := parts[1]
	if len(local) <= 3 {
		return local + "***@" + domain
	}
	return local[:3] + "***@" + domain
}

func inferIndicators(source string, content string, maxChars int) []ObservedIndicator {
	lower := strings.ToLower(content)
	var out []ObservedIndicator

	add := func(kind string, match string) {
		out = append(out, ObservedIndicator{
			Kind:   kind,
			Source: source,
			Match:  capAndRedact(match, maxChars),
		})
	}

	if strings.Contains(lower, "passwd") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") {
		add("credential", "mentions credential material (password/token/secret)")
	}
	if emailRE.MatchString(content) {
		add("pii", "contains email-like identifier")
	}
	if strings.Contains(lower, "ignore previous instructions") || strings.Contains(lower, "jailbreak") || strings.Contains(lower, "system prompt") {
		add("jailbreak", "contains jailbreak-style instruction")
	}
	if strings.Contains(lower, "rm -rf") || strings.Contains(lower, "drop table") {
		add("destructive", "contains potentially destructive operation")
	}
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		add("exfiltration", "contains outbound URL")
	}

	return out
}

func summarizeToolResult(content string) string {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return ""
	}
	// Heuristic: highlight common sensitive field names present in JSON outputs.
	lower := strings.ToLower(trimmed)
	fields := []string{"passwd", "password", "token", "secret", "api_key", "authorization"}
	var hits []string
	for _, f := range fields {
		if strings.Contains(lower, `"`+f+`"`) || strings.Contains(lower, f) {
			hits = append(hits, f)
		}
	}
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return "tool result references fields: " + strings.Join(hits, ", ")
}

func dedupeSnippets(snippets []ObservedSnippet) []ObservedSnippet {
	if len(snippets) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(snippets))
	out := make([]ObservedSnippet, 0, len(snippets))
	for _, s := range snippets {
		key := strings.ToLower(strings.TrimSpace(s.Type)) + "\n" + strings.TrimSpace(s.Content)
		if key == "\n" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dedupeIndicators(items []ObservedIndicator) []ObservedIndicator {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]ObservedIndicator, 0, len(items))
	for _, it := range items {
		key := strings.ToLower(strings.TrimSpace(it.Kind)) + "|" + strings.ToLower(strings.TrimSpace(it.Source)) + "|" + strings.TrimSpace(it.Match)
		if key == "||" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, it)
	}
	return out
}
