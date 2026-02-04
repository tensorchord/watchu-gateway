package parser

import (
	"encoding/json"
	"time"
)

// SystemEvent represents system initialization event
type SystemEvent struct {
	EventType string    `json:"type"`
	Subtype   string    `json:"subtype"`
	SessionID string    `json:"session_id"`
	CWD       string    `json:"cwd"`
	Tools     []string  `json:"tools"`
	MCPServers []string `json:"mcp_servers"`
	Model     string    `json:"model"`
	UUID      string    `json:"uuid"`
	timestamp time.Time `json:"-"`
}

func (e *SystemEvent) Type() string { return e.EventType }
func (e *SystemEvent) Timestamp() string {
	if e.timestamp.IsZero() {
		return time.Now().Format(time.RFC3339)
	}
	return e.timestamp.Format(time.RFC3339)
}
func (e *SystemEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// Message represents message structure (shared by Assistant and User)
type Message struct {
	ID      string          `json:"id"`
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content []MessageContent `json:"content"`
}

// MessageContent represents message content (text or tool call)
type MessageContent struct {
	Type      string                 `json:"type"` // "text" | "tool_use" | "tool_result"
	Text      string                 `json:"text,omitempty"`
	ID        string                 `json:"id,omitempty"`    // tool_use_id
	Name      string                 `json:"name,omitempty"`  // tool name
	Input     map[string]interface{} `json:"input,omitempty"` // tool input
	Content   interface{}            `json:"content,omitempty"` // tool result content
	IsError   bool                   `json:"is_error,omitempty"`
	ToolUseID string                 `json:"tool_use_id,omitempty"` // associated tool_use id
}

// AssistantEvent represents assistant message event
type AssistantEvent struct {
	EventType       string    `json:"type"`
	Message         Message   `json:"message"`
	ParentToolUseID string    `json:"parent_tool_use_id"`
	SessionID       string    `json:"session_id"`
	UUID            string    `json:"uuid"`
	timestamp       time.Time `json:"-"`
}

func (e *AssistantEvent) Type() string { return e.EventType }
func (e *AssistantEvent) Timestamp() string {
	if e.timestamp.IsZero() {
		return time.Now().Format(time.RFC3339)
	}
	return e.timestamp.Format(time.RFC3339)
}
func (e *AssistantEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// UserEvent represents user message event (mainly tool execution results)
type UserEvent struct {
	EventType     string                 `json:"type"`
	Message       Message                `json:"message"`
	SessionID     string                 `json:"session_id"`
	UUID          string                 `json:"uuid"`
	ToolUseResult map[string]interface{} `json:"tool_use_result,omitempty"`
	timestamp     time.Time              `json:"-"`
}

func (e *UserEvent) Type() string { return e.EventType }
func (e *UserEvent) Timestamp() string {
	if e.timestamp.IsZero() {
		return time.Now().Format(time.RFC3339)
	}
	return e.timestamp.Format(time.RFC3339)
}
func (e *UserEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// ResultEvent represents final result event
type ResultEvent struct {
	EventType      string                 `json:"type"`
	Subtype        string                 `json:"subtype"`
	IsError        bool                   `json:"is_error"`
	DurationMS     int                    `json:"duration_ms"`
	DurationAPIMS  int                    `json:"duration_api_ms"`
	NumTurns       int                    `json:"num_turns"`
	Result         string                 `json:"result"`
	SessionID      string                 `json:"session_id"`
	TotalCostUSD   float64                `json:"total_cost_usd"`
	Usage          map[string]interface{} `json:"usage"`
	ModelUsage     map[string]interface{} `json:"modelUsage"`
	UUID           string                 `json:"uuid"`
	timestamp      time.Time              `json:"-"`
}

func (e *ResultEvent) Type() string { return e.EventType }
func (e *ResultEvent) Timestamp() string {
	if e.timestamp.IsZero() {
		return time.Now().Format(time.RFC3339)
	}
	return e.timestamp.Format(time.RFC3339)
}
func (e *ResultEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// UnknownEvent represents unknown event type
type UnknownEvent struct {
	EventType string                 `json:"type"`
	RawData   map[string]interface{} `json:"raw_data"`
	timestamp time.Time              `json:"-"`
}

func (e *UnknownEvent) Type() string { return e.EventType }
func (e *UnknownEvent) Timestamp() string {
	if e.timestamp.IsZero() {
		return time.Now().Format(time.RFC3339)
	}
	return e.timestamp.Format(time.RFC3339)
}
func (e *UnknownEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}
