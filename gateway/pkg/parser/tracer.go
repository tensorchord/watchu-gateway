package parser

import (
	"time"
)

// ToolCall represents a tool call record
type ToolCall struct {
	CallID     string                 `json:"call_id"`
	Tool       string                 `json:"tool"`
	Input      map[string]interface{} `json:"input"`
	Output     interface{}            `json:"output"`
	IsError    bool                   `json:"is_error"`
	ErrorMsg   string                 `json:"error_msg,omitempty"`
	DurationMS int                    `json:"duration_ms,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// FileAccess represents a file access record
type FileAccess struct {
	FilePath  string    `json:"file_path"`
	Operation string    `json:"operation"` // read, write, edit, delete
	Tool      string    `json:"tool"`
	CallID    string    `json:"call_id"`
	Success   bool      `json:"success"`
	SizeBytes int64     `json:"size_bytes,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ExternalAccess represents an external access record
type ExternalAccess struct {
	Type      string                 `json:"type"` // bash_command, web_fetch, database_query
	Details   map[string]interface{} `json:"details"`
	Success   bool                   `json:"success"`
	Timestamp time.Time              `json:"timestamp"`
}

// ExecutionTrace represents the execution trace
type ExecutionTrace struct {
	AnalysisID     string            `json:"analysis_id"`
	SessionID      string            `json:"session_id"`
	Status         string            `json:"status"`
	DurationMS     int               `json:"duration_ms"`
	NumTurns       int               `json:"num_turns"`
	Model          string            `json:"model"`
	TotalCostUSD   float64           `json:"total_cost_usd"`
	ToolCalls      []ToolCall        `json:"tool_calls"`
	FileAccess     []FileAccess      `json:"file_access"`
	ExternalAccess []ExternalAccess  `json:"external_access"`
	Timeline       []TimelineEvent   `json:"timeline"`
	Errors         []ErrorRecord     `json:"errors,omitempty"`
	SecurityAlerts []SecurityAlert   `json:"security_alerts,omitempty"`
}

// TimelineEvent represents a timeline event
type TimelineEvent struct {
	Step      int                    `json:"step"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// ErrorRecord represents an error record
type ErrorRecord struct {
	Step          int    `json:"step"`
	Tool          string `json:"tool"`
	CallID        string `json:"call_id"`
	ErrorType     string `json:"error_type"`
	ErrorMessage  string `json:"error_message"`
	ExitCode      int    `json:"exit_code,omitempty"`
	RecoveryAction string `json:"recovery_action,omitempty"`
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	Severity     string `json:"severity"`
	FilePath     string `json:"file_path"`
	Line         int    `json:"line"`
	Issue        string `json:"issue"`
	Details      string `json:"details"`
	CodeSnippet  string `json:"code_snippet,omitempty"`
}

// ExecutionTracer is the execution trace builder
type ExecutionTracer struct {
	analysisID string
	stepCounter int
}

// NewExecutionTracer creates an execution tracer
func NewExecutionTracer(analysisID string) *ExecutionTracer {
	return &ExecutionTracer{
		analysisID: analysisID,
		stepCounter: 0,
	}
}

// Trace builds the execution trace
func (t *ExecutionTracer) Trace(events []Event) (*ExecutionTrace, error) {
	trace := &ExecutionTrace{
		AnalysisID:     t.analysisID,
		ToolCalls:      make([]ToolCall, 0),
		FileAccess:     make([]FileAccess, 0),
		ExternalAccess: make([]ExternalAccess, 0),
		Timeline:       make([]TimelineEvent, 0),
		Errors:         make([]ErrorRecord, 0),
		SecurityAlerts: make([]SecurityAlert, 0),
	}

	// Build tool call chain
	toolCalls := t.extractToolCalls(events)
	trace.ToolCalls = toolCalls

	// File access tracking
	fileAccess := t.extractFileAccess(events, toolCalls)
	trace.FileAccess = fileAccess

	// External access tracking
	externalAccess := t.extractExternalAccess(events, toolCalls)
	trace.ExternalAccess = externalAccess

	// Build timeline
	timeline := t.buildTimeline(events)
	trace.Timeline = timeline

	// Extract errors
	errors := t.extractErrors(events, toolCalls)
	trace.Errors = errors

	// Fill summary information
	t.fillSummary(trace, events)

	return trace, nil
}

// extractToolCalls extracts tool calls
func (t *ExecutionTracer) extractToolCalls(events []Event) []ToolCall {
	toolCalls := make([]ToolCall, 0)
	callMap := make(map[string]*ToolCall) // call_id -> tool_call

	for _, event := range events {
		switch e := event.(type) {
		case *AssistantEvent:
			for _, content := range e.Message.Content {
				if content.Type == "tool_use" {
					toolCall := ToolCall{
						CallID:    content.ID,
						Tool:      content.Name,
						Input:     content.Input,
						Timestamp: time.Now(),
					}
					callMap[content.ID] = &toolCall
					toolCalls = append(toolCalls, toolCall)
				}
			}

		case *UserEvent:
			for _, content := range e.Message.Content {
				if content.Type == "tool_result" && content.ToolUseID != "" {
					if call, exists := callMap[content.ToolUseID]; exists {
						call.Output = content.Content
						call.IsError = content.IsError
						if content.IsError {
							if str, ok := content.Content.(string); ok {
								call.ErrorMsg = str
							}
						}
						// Calculate duration (simplified, actual needs more precise timestamps)
						if !call.Timestamp.IsZero() {
							// Duration estimation - actual implementation needs more precise timing
							call.DurationMS = 0 // TODO: Implement proper duration calculation
						}
					}
				}
			}
		}
	}

	return toolCalls
}

// extractFileAccess extracts file access
func (t *ExecutionTracer) extractFileAccess(events []Event, toolCalls []ToolCall) []FileAccess {
	fileAccessList := make([]FileAccess, 0)

	for _, toolCall := range toolCalls {
		var filePath string
		var operation string

		switch toolCall.Tool {
		case "Read":
			if fp, ok := toolCall.Input["file_path"].(string); ok {
				filePath = fp
				operation = "read"
			}
		case "Write":
			if fp, ok := toolCall.Input["file_path"].(string); ok {
				filePath = fp
				operation = "write"
			}
		case "Edit":
			if fp, ok := toolCall.Input["file_path"].(string); ok {
				filePath = fp
				operation = "edit"
			}
		case "Bash":
			// Parse file operations from command
			if cmd, ok := toolCall.Input["command"].(string); ok {
				fileOps := t.parseFileOpsFromCommand(cmd)
				for _, fileOp := range fileOps {
					fileAccessList = append(fileAccessList, FileAccess{
						FilePath:  fileOp.Path,
						Operation: fileOp.Operation,
						Tool:      toolCall.Tool,
						CallID:    toolCall.CallID,
						Success:   !toolCall.IsError,
						Timestamp: toolCall.Timestamp,
					})
				}
				continue
			}
		}

		if filePath != "" {
			fileAccessList = append(fileAccessList, FileAccess{
				FilePath:  filePath,
				Operation: operation,
				Tool:      toolCall.Tool,
				CallID:    toolCall.CallID,
				Success:   !toolCall.IsError,
				Timestamp: toolCall.Timestamp,
			})
		}
	}

	return fileAccessList
}

// FileOp represents a file operation
type FileOp struct {
	Path      string
	Operation string
}

// parseFileOpsFromCommand parses file operations from Bash command
func (t *ExecutionTracer) parseFileOpsFromCommand(command string) []FileOp {
	// Simplified implementation, actual needs more complex parsing logic
	// TODO: Implement command parsing logic
	// - Detect ls, cat, head, tail, grep for read commands
	// - Detect touch, echo >, >> for write commands
	// - Detect rm, mv for delete/move commands
	return make([]FileOp, 0)
}

// extractExternalAccess extracts external access
func (t *ExecutionTracer) extractExternalAccess(events []Event, toolCalls []ToolCall) []ExternalAccess {
	externalAccessList := make([]ExternalAccess, 0)

	for _, toolCall := range toolCalls {
		switch toolCall.Tool {
		case "Bash":
			if cmd, ok := toolCall.Input["command"].(string); ok {
				externalAccessList = append(externalAccessList, ExternalAccess{
					Type: "bash_command",
					Details: map[string]interface{}{
						"command":   cmd,
						"exit_code": t.extractExitCode(toolCall.Output),
						"call_id":   toolCall.CallID,
					},
					Success:   !toolCall.IsError,
					Timestamp: toolCall.Timestamp,
				})
			}
		case "WebFetch":
			// Handle web requests
			if url, ok := toolCall.Input["url"].(string); ok {
				externalAccessList = append(externalAccessList, ExternalAccess{
					Type: "web_fetch",
					Details: map[string]interface{}{
						"url":     url,
						"call_id": toolCall.CallID,
					},
					Success:   !toolCall.IsError,
					Timestamp: toolCall.Timestamp,
				})
			}
		}
	}

	return externalAccessList
}

// extractExitCode extracts exit code from tool output
func (t *ExecutionTracer) extractExitCode(output interface{}) int {
	if m, ok := output.(map[string]interface{}); ok {
		if exitCode, ok := m["exitCode"].(float64); ok {
			return int(exitCode)
		}
	}
	return -1
}

// extractErrors extracts errors from events
func (t *ExecutionTracer) extractErrors(events []Event, toolCalls []ToolCall) []ErrorRecord {
	errors := make([]ErrorRecord, 0)
	step := 0

	for _, toolCall := range toolCalls {
		if toolCall.IsError {
			step++
			errors = append(errors, ErrorRecord{
				Step:         step,
				Tool:         toolCall.Tool,
				CallID:       toolCall.CallID,
				ErrorType:    t.classifyError(toolCall.ErrorMsg),
				ErrorMessage: toolCall.ErrorMsg,
				ExitCode:     t.extractExitCode(toolCall.Output),
			})
		}
	}

	return errors
}

// classifyError classifies error type from error message
func (t *ExecutionTracer) classifyError(errorMsg string) string {
	// Simplified error classification
	// TODO: Implement more sophisticated classification
	if errorMsg == "" {
		return "unknown"
	}
	return "generic"
}

// buildTimeline builds timeline
func (t *ExecutionTracer) buildTimeline(events []Event) []TimelineEvent {
	timeline := make([]TimelineEvent, 0)

	for _, event := range events {
		t.stepCounter++
		timelineEvent := TimelineEvent{
			Step:      t.stepCounter,
			Type:      event.Type(),
			Timestamp: t.extractTimestamp(event),
			Data:      make(map[string]interface{}),
		}

		// Fill data based on event type
		switch e := event.(type) {
		case *SystemEvent:
			timelineEvent.Data["cwd"] = e.CWD
			timelineEvent.Data["tools"] = e.Tools
			timelineEvent.Data["model"] = e.Model
		case *AssistantEvent:
			timelineEvent.Data["message_id"] = e.Message.ID
			toolUses := make([]string, 0)
			for _, content := range e.Message.Content {
				if content.Type == "tool_use" {
					toolUses = append(toolUses, content.Name)
				}
			}
			if len(toolUses) > 0 {
				timelineEvent.Data["tools_called"] = toolUses
			}
		case *ResultEvent:
			timelineEvent.Data["result"] = e.Result
			timelineEvent.Data["cost_usd"] = e.TotalCostUSD
			timelineEvent.Data["duration_ms"] = e.DurationMS
		}

		timeline = append(timeline, timelineEvent)
	}

	return timeline
}

// extractTimestamp extracts event timestamp
func (t *ExecutionTracer) extractTimestamp(event Event) time.Time {
	// Simplified implementation, actual needs to extract from event
	return time.Now()
}

// fillSummary fills summary information
func (t *ExecutionTracer) fillSummary(trace *ExecutionTrace, events []Event) {
	for _, event := range events {
		if e, ok := event.(*SystemEvent); ok {
			trace.SessionID = e.SessionID
			trace.Model = e.Model
		}
		if e, ok := event.(*ResultEvent); ok {
			trace.Status = e.Subtype
			trace.DurationMS = e.DurationMS
			trace.NumTurns = e.NumTurns
			trace.TotalCostUSD = e.TotalCostUSD
		}
	}
}
