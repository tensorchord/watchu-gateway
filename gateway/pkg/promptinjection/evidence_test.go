package promptinjection

import "testing"

func TestBuildObservedEvidence_ExtractsToolCallAndSnippets(t *testing.T) {
	raw := `{
		"messages": [
			{
				"role": "assistant",
				"tool_calls": [
					{
						"id": "call_1",
						"type": "function",
						"function": {
							"name": "query",
							"arguments": "{\"sql\":\"SELECT passwd FROM users WHERE email = 'allzhou@tensorchord.ai';\"}"
						}
					}
				]
			}
		]
	}`

	ev := buildObservedEvidence(raw, "full", 4096)
	if len(ev.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(ev.Calls))
	}
	if ev.Calls[0].ToolName != "query" {
		t.Fatalf("expected tool_name=query, got %q", ev.Calls[0].ToolName)
	}
	if ev.Calls[0].Arguments == "" {
		t.Fatalf("expected arguments to be present")
	}
	if len(ev.Calls[0].Snippets) == 0 {
		t.Fatalf("expected snippets to be extracted")
	}

	foundSQL := false
	for _, snip := range ev.Calls[0].Snippets {
		if snip.Type == "sql" {
			foundSQL = true
			if snip.Content == "" {
				t.Fatalf("expected sql snippet content")
			}
			// Email should be masked.
			if contains(snip.Content, "allzhou@tensorchord.ai") {
				t.Fatalf("expected email to be redacted in snippet content: %q", snip.Content)
			}
		}
	}
	if !foundSQL {
		t.Fatalf("expected at least one sql snippet")
	}
}

func TestBuildObservedEvidence_Latin1JSONFallback(t *testing.T) {
	// Simulate a raw_request stored as LATIN1-decoded text containing non-UTF8 bytes in strings.
	// The JSON structure is still parseable and tool call extraction should work.
	raw := "{\"messages\":[{\"role\":\"assistant\",\"tool_calls\":[{\"type\":\"function\",\"function\":{\"name\":\"query\",\"arguments\":\"{\\\"sql\\\":\\\"SELECT passwd FROM users\\\"}\"}}]}],\"model\":\"gpt-4o\"}"
	ev := buildObservedEvidence(raw, "standard", 4096)
	if len(ev.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(ev.Calls))
	}
	if ev.Calls[0].ToolName != "query" {
		t.Fatalf("expected tool_name=query, got %q", ev.Calls[0].ToolName)
	}
}

func TestBuildObservedEvidence_GeminiFormat_FunctionCallAndResponse(t *testing.T) {
	raw := `{
		"contents": [
			{
				"parts": [
					{
						"text": "describe the project"
					}
				],
				"role": "user"
			},
			{
				"parts": [
					{
						"functionCall": {
							"name": "read_file",
							"args": {
								"absolute_path": "/home/xieyuandong/llm-observability/test/kvdb/kvdb/Cargo.toml"
							}
						}
					}
				],
				"role": "model"
			},
			{
				"parts": [
					{
						"functionResponse": {
							"id": "read_file-xxx",
							"name": "read_file",
							"response": {
								"output": "[package]\nname = \"kvdb\"\n"
							}
						}
					}
				],
				"role": "user"
			}
		]
	}`

	ev := buildObservedEvidence(raw, "full", 4096)
	if len(ev.Calls) == 0 {
		t.Fatalf("expected calls to be extracted from gemini contents")
	}
	var foundCall bool
	var foundResponse bool
	for _, call := range ev.Calls {
		if call.ToolName != "read_file" {
			continue
		}
		if call.Arguments != "" && contains(call.Arguments, "Cargo.toml") {
			foundCall = true
		}
		if call.ResultHint != "" && contains(call.ResultHint, "kvdb") {
			foundResponse = true
		}
	}
	if !foundCall {
		t.Fatalf("expected to extract read_file functionCall with arguments")
	}
	if !foundResponse {
		t.Fatalf("expected to extract read_file functionResponse with output")
	}
}

func TestBuildObservedEvidence_ClaudeCodeFormat_ToolCalls(t *testing.T) {
	raw := `{
		"messages": [
			{
				"role": "assistant",
				"content": [
					{ "type": "text", "text": "You are Claude Code..." }
				]
			},
			{
				"role": "user",
				"content": [
					{ "type": "text", "text": "<system-reminder>...</system-reminder>" },
					{ "type": "text", "text": "Search for Rust learning articles" }
				]
			},
			{
				"role": "assistant",
				"tool_calls": [
					{
						"id": "call_123",
						"type": "function",
						"function": {
							"name": "mcp__exa__web_search_exa",
							"arguments": "query"
						}
					}
				],
				"content": null
			}
		],
		"model": "gpt-4o"
	}`

	ev := buildObservedEvidence(raw, "standard", 4096)
	if len(ev.Calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(ev.Calls))
	}
	if ev.Calls[0].ToolName != "mcp__exa__web_search_exa" {
		t.Fatalf("expected tool_name=mcp__exa__web_search_exa, got %q", ev.Calls[0].ToolName)
	}
	if ev.Calls[0].Arguments == "" {
		t.Fatalf("expected arguments to be present")
	}
}

func TestParseGuardrailResponse_JSON(t *testing.T) {
	resp := `{
		"safety": "unsafe",
		"categories": ["Personally Identifiable Information", "Unethical Acts"],
		"score": 0.91,
		"reason": "Observed in the request: ...",
		"evidence": [
			{
				"id": "e1",
				"type": "indicator",
				"source": "tool_args",
				"severity": "high",
				"quote": "SELECT passwd FROM users",
				"interpretation": "This attempts to retrieve credential material."
			}
		]
	}`

	parsed := ParseGuardrailResponse(resp)
	if parsed.Safety != "unsafe" {
		t.Fatalf("expected safety unsafe, got %q", parsed.Safety)
	}
	if parsed.Score < 0.9 {
		t.Fatalf("expected score to parse, got %v", parsed.Score)
	}
	if parsed.Reason == "" {
		t.Fatalf("expected reason to parse")
	}
	if len(parsed.Evidence) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(parsed.Evidence))
	}
}

func TestValidateGuardrailEvidence_RequiresExactSubstring(t *testing.T) {
	input := `{"user_input":"hi","observed_evidence":{"calls":[{"tool_name":"query","arguments":"SELECT passwd FROM users"}]}}`
	items := []GuardrailEvidence{
		{ID: "e1", Quote: "SELECT passwd FROM users", Type: "snippet", Source: "tool_args", Severity: "high", Interpretation: "ok"},
		{ID: "e2", Quote: "NOT PRESENT", Type: "snippet", Source: "tool_args", Severity: "high", Interpretation: "bad"},
	}
	out := validateGuardrailEvidence(items, input)
	if len(out) != 1 {
		t.Fatalf("expected 1 validated item, got %d", len(out))
	}
	if out[0].ID != "e1" {
		t.Fatalf("expected e1, got %q", out[0].ID)
	}
}
