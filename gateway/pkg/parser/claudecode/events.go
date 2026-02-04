package claudecode

import (
	"encoding/json"
	"time"
)

// Event represents a parsed event from runner output
type Event struct {
	EventType string `json:"type"`
	// System event fields
	Subtype     string   `json:"subtype,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	CWD         string   `json:"cwd,omitempty"`
	Tools       []string `json:"tools,omitempty"`
	MCPServers  []string `json:"mcp_servers,omitempty"`
	Model       string   `json:"model,omitempty"`
	UUID        string   `json:"uuid,omitempty"`
	// Message event fields
	Message         *Message          `json:"message,omitempty"`
	ParentToolUseID string            `json:"parent_tool_use_id,omitempty"`
	ToolUseResult   map[string]interface{} `json:"tool_use_result,omitempty"`
	// Result event fields
	IsError       bool                   `json:"is_error,omitempty"`
	DurationMS    int                    `json:"duration_ms,omitempty"`
	DurationAPIMS int                    `json:"duration_api_ms,omitempty"`
	NumTurns      int                    `json:"num_turns,omitempty"`
	Result        string                 `json:"result,omitempty"`
	TotalCostUSD  float64                `json:"total_cost_usd,omitempty"`
	Usage         map[string]interface{} `json:"usage,omitempty"`
	ModelUsage    map[string]interface{} `json:"modelUsage,omitempty"`
	// Common fields
	RawData   map[string]interface{} `json:"raw_data,omitempty"`
	Timestamp time.Time              `json:"-"`
}

// Type returns the event type
func (e *Event) Type() string {
	return e.EventType
}

// TimestampString returns the timestamp as a string
func (e *Event) TimestampString() string {
	if e.Timestamp.IsZero() {
		return time.Now().Format(time.RFC3339)
	}
	return e.Timestamp.Format(time.RFC3339)
}

// ToJSON converts the event to JSON
func (e *Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// Message represents a message structure
type Message struct {
	ID      string          `json:"id"`
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content []MessageContent `json:"content"`
}

// MessageContent represents message content
type MessageContent struct {
	Type      string                 `json:"type"`
	Text      string                 `json:"text,omitempty"`
	ID        string                 `json:"id,omitempty"`
	Name      string                 `json:"name,omitempty"`
	Input     map[string]interface{} `json:"input,omitempty"`
	Content   interface{}            `json:"content,omitempty"`
	IsError   bool                   `json:"is_error,omitempty"`
	ToolUseID string                 `json:"tool_use_id,omitempty"`
}
