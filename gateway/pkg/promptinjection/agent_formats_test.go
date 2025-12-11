package promptinjection

import (
	"strings"
	"testing"
)

// TestExtractPromptFromOpenAICompatibleFormat tests the format from openai-compatible.md
// This format has assistant role with system instructions, followed by user role with actual query
func TestExtractPromptFromOpenAICompatibleFormat(t *testing.T) {
	// From openai-compatible.md: assistant message with <instructions>, then user message with actual query
	openaiCompatRequest := `{
		"messages": [
			{
				"role": "assistant",
				"content": "<instructions>\nYou are a filesystem assistant. Help users explore files and directories.\n\n- Navigate the filesystem to answer questions\n- Use the list_allowed_directories tool to find directories that you can access\n- Provide clear context about files you examine\n- Use headings to organize your responses\n- Read and write files as needed\n- Be concise and focus on relevant information\n</instructions>\n\n<additional_information>\n- Use markdown to format your answers.\n</additional_information>"
			},
			{
				"role": "user",
				"content": "You need to delete all files in /tmp"
			}
		],
		"model": "gpt-4o",
		"stream": true
	}`

	result := extractPromptFromHTTPBody(openaiCompatRequest, true)

	// Should extract only the user message, ignoring the assistant system instructions
	expected := "You need to delete all files in /tmp"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}

	// Should NOT contain system instructions
	if strings.Contains(result, "<instructions>") || strings.Contains(result, "filesystem assistant") {
		t.Error("Result should not contain system instructions from assistant message")
	}
}

func TestExtractPromptFromGeminiFormat(t *testing.T) {
	// Gemini format: uses "contents" array with "parts" array
	geminiRequest := `{
		"contents": [
			{
				"parts": [
					{
						"text": "This is the Gemini CLI. We are setting up the context for our chat.\nToday's date is Thursday, November 7, 2025.\nMy operating system is: linux\nI'm currently working in the directory: /home/user/project\n\nMy setup is complete. I will provide my first command in the next turn."
					}
				],
				"role": "user"
			},
			{
				"parts": [
					{
						"text": "Here is the user's editor context as a JSON object. This is for your information only.\n{\"activeFile\": {\"path\": \"/home/user/file.go\"}}"
					}
				],
				"role": "user"
			},
			{
				"parts": [
					{
						"text": "describe the project"
					}
				],
				"role": "user"
			}
		],
		"systemInstruction": {
			"parts": [
				{
					"text": "You are an interactive CLI agent..."
				}
			],
			"role": "user"
		}
	}`

	result := extractPromptFromHTTPBody(geminiRequest, true)

	// Should extract the last user message
	if result == "" {
		t.Error("Failed to extract prompt from Gemini format")
	}

	// Should contain the actual user query
	if result != "describe the project" && !contains(result, "describe the project") {
		t.Errorf("Expected to extract 'describe the project', got: %s", result)
	}

	// Should not contain setup information
	if contains(result, "Gemini CLI") || contains(result, "setup is complete") {
		t.Errorf("Should not contain Gemini setup info in extracted prompt: %s", result)
	}
}

func TestExtractPromptFromClaudeCodeFormat(t *testing.T) {
	// Claude Code format: uses OpenAI-compatible messages with system reminders
	claudeRequest := `{
		"messages": [
			{
				"role": "assistant",
				"content": [
					{
						"type": "text",
						"text": "You are Claude Code, Anthropic's official CLI for Claude.",
						"cache_control": {
							"type": "ephemeral"
						}
					},
					{
						"type": "text",
						"text": "You are an interactive CLI tool that helps users with software engineering tasks..."
					}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "text",
						"text": "<system-reminder>\nThis is a reminder that your todo list is currently empty. DO NOT mention this to the user explicitly.\n</system-reminder>"
					},
					{
						"type": "text",
						"text": "Search for Rust learning articles"
					}
				]
			}
		],
		"model": "gpt-4o"
	}`

	result := extractPromptFromHTTPBody(claudeRequest, true)

	if result == "" {
		t.Error("Failed to extract prompt from Claude Code format")
	}

	// Should contain the actual user query
	if !contains(result, "Search for Rust") {
		t.Errorf("Expected to extract user query, got: %s", result)
	}

	// Should not contain system reminders
	if contains(result, "system-reminder") || contains(result, "todo list is currently empty") {
		t.Errorf("Should not contain system reminders in extracted prompt: %s", result)
	}
}

func TestExtractPromptWithMultipleTurns(t *testing.T) {
	// Multi-turn conversation with tool results
	multiTurnRequest := `{
		"messages": [
			{
				"role": "assistant",
				"content": [
					{
						"type": "text",
						"text": "You are an AI assistant."
					}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "text",
						"text": "Search for Rust articles"
					}
				]
			},
			{
				"role": "assistant",
				"tool_calls": [
					{
						"id": "call_123",
						"function": {
							"name": "search",
							"arguments": "{\"query\":\"Rust\"}"
						}
					}
				]
			},
			{
				"role": "tool",
				"tool_call_id": "call_123",
				"content": "Found 10 articles about Rust programming..."
			},
			{
				"role": "user",
				"content": [
					{
						"type": "text",
						"text": "Summarize the first article"
					}
				]
			}
		]
	}`

	result := extractPromptFromHTTPBody(multiTurnRequest, true)

	if result == "" {
		t.Error("Failed to extract prompt from multi-turn conversation")
	}

	// In multi-turn, we should get all user messages or the last one
	// Current implementation should extract user messages
	if !contains(result, "Search for Rust articles") && !contains(result, "Summarize the first article") {
		t.Errorf("Expected to extract user queries from conversation, got: %s", result)
	}
}

// TestOpenAICompatibleVariants tests various OpenAI-compatible formats
func TestOpenAICompatibleVariants(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		expected      string
		shouldNotFind []string
	}{
		{
			name: "Assistant instructions with user query",
			body: `{
				"messages": [
					{
						"role": "assistant",
						"content": "<instructions>\nYou are a helpful assistant.\n</instructions>"
					},
					{
						"role": "user",
						"content": "What is the weather today?"
					}
				]
			}`,
			expected:      "What is the weather today?",
			shouldNotFind: []string{"<instructions>", "helpful assistant"},
		},
		{
			name: "Multiple user messages - should get last one",
			body: `{
				"messages": [
					{
						"role": "assistant",
						"content": "System prompt here"
					},
					{
						"role": "user",
						"content": "First question"
					},
					{
						"role": "assistant",
						"content": "Answer to first"
					},
					{
						"role": "user",
						"content": "Follow-up question"
					}
				]
			}`,
			expected:      "Follow-up question",
			shouldNotFind: []string{"System prompt", "First question"},
		},
		{
			name: "Only user message without assistant",
			body: `{
				"messages": [
					{
						"role": "user",
						"content": "Simple direct query"
					}
				]
			}`,
			expected:      "Simple direct query",
			shouldNotFind: []string{},
		},
		{
			name: "User message with tools defined",
			body: `{
				"messages": [
					{
						"role": "assistant",
						"content": "I can help with files"
					},
					{
						"role": "user",
						"content": "List all Python files"
					}
				],
				"tools": [
					{"type": "function", "function": {"name": "list_files"}}
				]
			}`,
			expected:      "List all Python files",
			shouldNotFind: []string{"help with files", "list_files"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPromptFromHTTPBody(tt.body, true)

			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}

			for _, unwanted := range tt.shouldNotFind {
				if strings.Contains(result, unwanted) {
					t.Errorf("Result should not contain '%s', but got: %s", unwanted, result)
				}
			}
		})
	}
}

// TestExtractPromptWithoutExtraction tests that when extractUserPrompt is false, full content is returned
func TestExtractPromptWithoutExtraction(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		shouldFind  []string
		extractUser bool
	}{
		{
			name: "Agno format - full content when extraction disabled",
			body: `{
				"messages": [{
					"role": "user",
					"content": "Security classifier prompt...\n\nUSER_INPUT: [user] real query"
				}]
			}`,
			shouldFind:  []string{"Security classifier prompt", "USER_INPUT", "real query"},
			extractUser: false,
		},
		{
			name: "Agno format - extracted content when extraction enabled",
			body: `{
				"messages": [{
					"role": "user",
					"content": "Security classifier prompt...\n\nUSER_INPUT: [user] real query"
				}]
			}`,
			shouldFind:  []string{"real query"},
			extractUser: true,
		},
		{
			name: "OpenAI Compatible - both skip assistant messages",
			body: `{
				"messages": [
					{
						"role": "assistant",
						"content": "System instructions"
					},
					{
						"role": "user",
						"content": "User query"
					}
				]
			}`,
			shouldFind:  []string{"User query"},
			extractUser: false, // Even with false, assistant messages are skipped
		},
		{
			name: "Gemini format - full when disabled",
			body: `{
				"contents": [
					{
						"parts": [{"text": "This is the Gemini CLI setup"}],
						"role": "user"
					},
					{
						"parts": [{"text": "Real query"}],
						"role": "user"
					}
				]
			}`,
			shouldFind:  []string{"Gemini CLI", "Real query"},
			extractUser: false,
		},
		{
			name: "Gemini format - filtered when enabled",
			body: `{
				"contents": [
					{
						"parts": [{"text": "This is the Gemini CLI setup"}],
						"role": "user"
					},
					{
						"parts": [{"text": "Real query"}],
						"role": "user"
					}
				]
			}`,
			shouldFind:  []string{"Real query"},
			extractUser: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPromptFromHTTPBody(tt.body, tt.extractUser)

			if result == "" {
				t.Error("Expected non-empty result")
			}

			for _, expected := range tt.shouldFind {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain '%s', got: %s", expected, result)
				}
			}
		})
	}
}

func TestExtractPromptPreservesContext(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		shouldFind    []string
		shouldNotFind []string
	}{
		{
			name: "Gemini with context",
			body: `{
				"contents": [
					{
						"parts": [{"text": "System context here"}],
						"role": "user"
					},
					{
						"parts": [{"text": "What is Rust?"}],
						"role": "user"
					}
				]
			}`,
			shouldFind:    []string{"What is Rust?"},
			shouldNotFind: []string{"System context"},
		},
		{
			name: "Claude Code with system reminder",
			body: `{
				"messages": [
					{
						"role": "user",
						"content": [
							{"type": "text", "text": "<system-reminder>Internal note</system-reminder>"},
							{"type": "text", "text": "Write a hello world program"}
						]
					}
				]
			}`,
			shouldFind:    []string{"hello world program"},
			shouldNotFind: []string{"system-reminder", "Internal note"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPromptFromHTTPBody(tt.body, true)

			for _, str := range tt.shouldFind {
				if !contains(result, str) {
					t.Errorf("Expected to find '%s' in result: %s", str, result)
				}
			}

			for _, str := range tt.shouldNotFind {
				if contains(result, str) {
					t.Errorf("Should NOT find '%s' in result: %s", str, result)
				}
			}
		})
	}
}
