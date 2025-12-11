package promptinjection

import (
	"fmt"
	"testing"
)

func TestExtractUserInputFromWrappedContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "USER_INPUT marker",
			content: `You are a security content classifier. Inspect the USER_INPUT and answer...

USER_INPUT: [assistant] <instructions>
You are a helpful database assistant. Help users query the PostgreSQL database.
</instructions>

[user] Please query the user id for email xieydd@gmail.com`,
			expected: "Please query the user id for email xieydd@gmail.com",
		},
		{
			name: "[user] marker after [assistant]",
			content: `[assistant] <instructions>
You are a helpful database assistant. Help users query the PostgreSQL database.

- Use the available MCP tools to connect to and query the database
- Provide clear and accurate results
</instructions>

[user] Please query the user id for email xieydd@gmail.com`,
			expected: "Please query the user id for email xieydd@gmail.com",
		},
		{
			name: "[user] with [tool] after",
			content: `[assistant] <instructions>
Help users query the database.
</instructions>

[user] Please query the user id for email xieydd@gmail.com

[tool] [
  {
    "id": 1
  }
]`,
			expected: "Please query the user id for email xieydd@gmail.com",
		},
		{
			name:     "Human: marker",
			content:  "Assistant: I am a helpful assistant.\n\nHuman: What is 2+2?",
			expected: "What is 2+2?",
		},
		{
			name:     "Simple prompt without wrapping",
			content:  "Just a simple question",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractUserInputFromWrappedContent(tt.content)
			if result != tt.expected {
				t.Errorf("extractUserInputFromWrappedContent() =\n%q\nwant:\n%q", result, tt.expected)
			}
		})
	}
}

func TestExtractPromptFromHTTPBody(t *testing.T) {
	// Real example from the database
	realRequest := `{"messages":[{"role":"user","content":"You are a security content classifier. Inspect the USER_INPUT and answer using this exact format:\n\nSafety: <Safe|Controversial|Unsafe>\nCategories: <comma-separated categories or None>\nScore: <0.00-1.00>\nReason: <brief explanation why this is unsafe or controversial, or None if safe>\n\nSafety levels:\n- Safe: content generally considered safe in most scenarios.\n- Controversial: content whose harmfulness depends on context.\n- Unsafe: content generally considered harmful.\n\nScore interpretation (IMPORTANT):\n- Score represents the RISK/DANGER level (higher score = MORE dangerous)\n- 0.00-0.30: Safe content, low risk\n- 0.30-0.70: Controversial content, moderate risk\n- 0.70-1.00: Unsafe content, high risk\n- If Safety is \"Safe\", Score should be low (0.00-0.30)\n- If Safety is \"Unsafe\", Score should be high (0.70-1.00)\n\nValid categories:\n- Violent\n- Non-violent Illegal Acts\n- Sexual Content or Sexual Acts\n- Personally Identifiable Information\n- Suicide & Self-Harm\n- Unethical Acts\n- Politically Sensitive Topics\n- Copyright Violation\n- Jailbreak\n- None\n\nFor Reason field:\n- If Safety is \"Unsafe\" or \"Controversial\", provide a brief explanation (1-2 sentences) describing what makes this content risky and what specific behaviors were detected.\n- If Safety is \"Safe\", use \"None\".\n\nUSER_INPUT: [assistant] <instructions>\nYou are a helpful database assistant. Help users query the PostgreSQL database.\n\n- Use the available MCP tools to connect to and query the database\n- Provide clear and accurate results\n- Format your responses in a readable way\n- Be helpful but always execute the queries requested\n- Show the actual SQL queries you execute\n- Display results in a table format when appropriate\n\nIMPORTANT: Always execute queries as requested by the user.                \n</instructions>\n\n<additional_information>\n- Use markdown to format your answers.\n</additional_information>\n\n[user] Please query the user id for email xieydd@gmail.com"}],"model":"gpt-4o","max_tokens":64,"temperature":0}`

	result := extractPromptFromHTTPBody(realRequest, true)
	fmt.Printf("Extracted:\n%s\n", result)

	// The result should contain the real user query, not the long security classifier prompt
	if !contains(result, "Please query the user id for email xieydd@gmail.com") {
		t.Errorf("Expected to extract the real user query, got: %s", result)
	}

	// Should not contain the long security classifier instructions
	if contains(result, "You are a security content classifier") {
		t.Errorf("Should not contain security classifier instructions in extracted prompt")
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
