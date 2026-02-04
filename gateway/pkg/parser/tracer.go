package parser

import (
	"strings"
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

// Command represents a bash command execution record
type Command struct {
	Command   string                 `json:"command"`
	ExitCode  int                    `json:"exit_code,omitempty"`
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
	Commands       []Command         `json:"commands"`
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
		Commands:       make([]Command, 0),
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

	// Command execution tracking - all bash commands
	commands := t.extractCommands(toolCalls)
	trace.Commands = commands

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
				if len(fileOps) > 0 {
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
	fileOps := make([]FileOp, 0)

	// Trim whitespace and get the first word (command name)
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return fileOps
	}

	// Split by command separators to handle compound commands like "cmd1 && cmd2"
	// We only parse the first command before &&, ||, or ;
	firstCmd := t.extractFirstCommand(cmd)
	if firstCmd == "" {
		return fileOps
	}

	// Split by spaces to get command and args
	parts := strings.Fields(firstCmd)
	if len(parts) == 0 {
		return fileOps
	}

	cmdName := parts[0]

	switch cmdName {
	case "mkdir", "mkdirs", "makedirs":
		// mkdir: create directory
		if len(parts) > 1 {
			for _, arg := range parts[1:] {
				if !strings.HasPrefix(arg, "-") { // Skip flags like -p, -v, etc.
					fileOps = append(fileOps, FileOp{
						Path:      arg,
						Operation: "create_dir",
					})
				}
			}
		}

	case "touch":
		// touch: create empty file
		if len(parts) > 1 {
			for _, arg := range parts[1:] {
				fileOps = append(fileOps, FileOp{
					Path:      arg,
					Operation: "create",
				})
			}
		}

	case "rm", "rmdir":
		// rm/rmdir: delete file or directory
		if len(parts) > 1 {
			for _, arg := range parts[1:] {
				if !strings.HasPrefix(arg, "-") {
					fileOps = append(fileOps, FileOp{
						Path:      arg,
						Operation: "delete",
					})
				}
			}
		}

	case "mv":
		// mv: move/rename file (source -> destination)
		if len(parts) >= 3 {
			// Skip flags, find source and destination
			args := parts[1:]
			nonFlags := make([]string, 0)
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-") {
					nonFlags = append(nonFlags, arg)
				}
			}
			if len(nonFlags) >= 2 {
				fileOps = append(fileOps, FileOp{
					Path:      nonFlags[0], // source
					Operation: "move",
				})
			}
		}

	case "cp":
		// cp: copy file
		if len(parts) >= 3 {
			args := parts[1:]
			nonFlags := make([]string, 0)
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-") {
					nonFlags = append(nonFlags, arg)
				}
			}
			if len(nonFlags) >= 1 {
				fileOps = append(fileOps, FileOp{
					Path:      nonFlags[0], // source
					Operation: "read",
				})
			}
		}

	case "ls", "ll", "la", "lla":
		// ls: list directory (read operation)
		// The directory path is usually the last non-flag argument
		if len(parts) > 1 {
			lastArg := parts[len(parts)-1]
			if !strings.HasPrefix(lastArg, "-") {
				fileOps = append(fileOps, FileOp{
					Path:      lastArg,
					Operation: "read",
				})
			}
		}

	case "cat", "head", "tail", "less", "more":
		// Read file contents
		if len(parts) > 1 {
			for _, arg := range parts[1:] {
				if !strings.HasPrefix(arg, "-") {
					fileOps = append(fileOps, FileOp{
						Path:      arg,
						Operation: "read",
					})
				}
			}
		}

	case "grep", "rg", "ag":
		// Grep: read file(s) to search
		// The file path is usually the last argument(s)
		if len(parts) > 1 {
			lastIdx := len(parts) - 1
			if !strings.HasPrefix(parts[lastIdx], "-") {
				fileOps = append(fileOps, FileOp{
					Path:      parts[lastIdx],
					Operation: "read",
				})
			}
		}

	case "find":
		// find: search files in directory
		if len(parts) > 1 {
			// First non-flag argument is usually the start directory
			for _, arg := range parts[1:] {
				if !strings.HasPrefix(arg, "-") {
					fileOps = append(fileOps, FileOp{
						Path:      arg,
						Operation: "read",
					})
					break // Only take the first non-flag as directory
				}
			}
		}

	case "echo":
		// Check if output is redirected to a file (> or >>)
		for i, arg := range parts {
			if arg == ">" || arg == ">>" {
				if i+1 < len(parts) {
					fileOps = append(fileOps, FileOp{
						Path:      parts[i+1],
						Operation: "write",
					})
					break
				}
			}
		}

	case "tee":
		// tee: read stdin and write to file(s)
		if len(parts) > 1 {
			for _, arg := range parts[1:] {
				if !strings.HasPrefix(arg, "-") {
					fileOps = append(fileOps, FileOp{
						Path:      arg,
						Operation: "write",
					})
				}
			}
		}

	case "chmod", "chown":
		// chmod/chown: modify file metadata
		if len(parts) > 1 {
			// File path is usually the last argument
			lastArg := parts[len(parts)-1]
			if !strings.HasPrefix(lastArg, "-") {
				fileOps = append(fileOps, FileOp{
					Path:      lastArg,
					Operation: "metadata",
				})
			}
		}

	case "ln":
		// ln: create link
		if len(parts) >= 3 {
			args := parts[1:]
			nonFlags := make([]string, 0)
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-") {
					nonFlags = append(nonFlags, arg)
				}
			}
			if len(nonFlags) >= 2 {
				fileOps = append(fileOps, FileOp{
					Path:      nonFlags[1], // link name
					Operation: "create",
				})
			}
		}
	}

	return fileOps
}

// extractFirstCommand extracts the first command before &&, ||, or ;
// This handles compound commands like "mkdir dir && cd dir && ls"
func (t *ExecutionTracer) extractFirstCommand(command string) string {
	// Find the first occurrence of a command separator
	separators := []string{"&&", "||", ";"}

	lowestIdx := -1
	for _, sep := range separators {
		idx := strings.Index(command, sep)
		if idx != -1 && (lowestIdx == -1 || idx < lowestIdx) {
			lowestIdx = idx
		}
	}

	if lowestIdx == -1 {
		return command // No separator found, return entire command
	}

	// Return only the part before the first separator
	return strings.TrimSpace(command[:lowestIdx])
}

// extractCommands extracts bash command executions
func (t *ExecutionTracer) extractCommands(toolCalls []ToolCall) []Command {
	commands := make([]Command, 0)

	for _, toolCall := range toolCalls {
		if toolCall.Tool == "Bash" {
			if cmd, ok := toolCall.Input["command"].(string); ok {
				commands = append(commands, Command{
					Command:   cmd,
					ExitCode:  t.extractExitCode(toolCall.Output),
					Success:   !toolCall.IsError,
					Timestamp: toolCall.Timestamp,
				})
			}
		}
	}

	return commands
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
