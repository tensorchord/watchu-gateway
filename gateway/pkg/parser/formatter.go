package parser

import (
	"encoding/json"
)

// TraceFormatter is the trace formatter
type TraceFormatter struct{}

// NewTraceFormatter creates a formatter
func NewTraceFormatter() *TraceFormatter {
	return &TraceFormatter{}
}

// ExecutionSummary represents execution summary
type ExecutionSummary struct {
	AnalysisID        string   `json:"analysis_id"`
	SessionID         string   `json:"session_id"`
	Status            string   `json:"status"`
	DurationMS        int      `json:"duration_ms"`
	DurationAPIMS     int      `json:"duration_api_ms,omitempty"`
	NumTurns          int      `json:"num_turns"`
	Model             string   `json:"model"`
	TotalCostUSD      float64  `json:"total_cost_usd"`
	ToolsUsed         []string `json:"tools_used"`
	FilesAccessed     int      `json:"files_accessed"`
	CommandsExecuted  int      `json:"commands_executed"`
	ErrorsEncountered int      `json:"errors_encountered"`
	SecurityAlerts    int      `json:"security_alerts"`
}

// ToolUsageStats represents tool usage statistics
type ToolUsageStats struct {
	ToolUsage map[string]ToolStats `json:"tool_usage"`
}

// ToolStats represents statistics for a single tool
type ToolStats struct {
	Count   int        `json:"count"`
	Success int        `json:"success"`
	Failed  int        `json:"failed"`
	Calls   []ToolCall `json:"calls"`
}

// FormatSummary generates execution summary
func (f *TraceFormatter) FormatSummary(trace *ExecutionTrace) *ExecutionSummary {
	// Count tools used
	toolsUsed := make(map[string]bool)
	for _, call := range trace.ToolCalls {
		toolsUsed[call.Tool] = true
	}

	toolsList := make([]string, 0, len(toolsUsed))
	for tool := range toolsUsed {
		toolsList = append(toolsList, tool)
	}

	// Count command executions
	commandsExecuted := 0
	for _, call := range trace.ToolCalls {
		if call.Tool == "Bash" {
			commandsExecuted++
		}
	}

	return &ExecutionSummary{
		AnalysisID:        trace.AnalysisID,
		SessionID:         trace.SessionID,
		Status:            trace.Status,
		DurationMS:        trace.DurationMS,
		NumTurns:          trace.NumTurns,
		Model:             trace.Model,
		TotalCostUSD:      trace.TotalCostUSD,
		ToolsUsed:         toolsList,
		FilesAccessed:     len(trace.FileAccess),
		CommandsExecuted:  commandsExecuted,
		ErrorsEncountered: len(trace.Errors),
		SecurityAlerts:    len(trace.SecurityAlerts),
	}
}

// FormatTimeline generates timeline
func (f *TraceFormatter) FormatTimeline(trace *ExecutionTrace) []TimelineEvent {
	return trace.Timeline
}

// FormatToolUsage generates tool usage statistics
func (f *TraceFormatter) FormatToolUsage(trace *ExecutionTrace) *ToolUsageStats {
	stats := &ToolUsageStats{
		ToolUsage: make(map[string]ToolStats),
	}

	for _, call := range trace.ToolCalls {
		toolStats, exists := stats.ToolUsage[call.Tool]
		if !exists {
			toolStats = ToolStats{
				Count:   0,
				Success: 0,
				Failed:  0,
				Calls:   make([]ToolCall, 0),
			}
		}

		toolStats.Count++
		if call.IsError {
			toolStats.Failed++
		} else {
			toolStats.Success++
		}
		toolStats.Calls = append(toolStats.Calls, call)

		stats.ToolUsage[call.Tool] = toolStats
	}

	return stats
}

// FileAccessDetails represents file access details
type FileAccessDetails struct {
	FilesAccessed     []FileAccessInfo `json:"files_accessed"`
	DirectoriesListed []string         `json:"directories_listed"`
}

// FileAccessInfo represents file access information (aggregates multiple operations on the same file)
type FileAccessInfo struct {
	Path           string         `json:"path"`
	Operations     []FileAccess   `json:"operations"`
	SecurityIssues []SecurityAlert `json:"security_issues,omitempty"`
}

// FormatFileAccess generates file access details
func (f *TraceFormatter) FormatFileAccess(trace *ExecutionTrace) *FileAccessDetails {
	details := &FileAccessDetails{
		FilesAccessed:     make([]FileAccessInfo, 0),
		DirectoriesListed: make([]string, 0),
	}

	// Aggregate operations by file path
	fileMap := make(map[string]*FileAccessInfo)
	for _, access := range trace.FileAccess {
		info, exists := fileMap[access.FilePath]
		if !exists {
			info = &FileAccessInfo{
				Path:           access.FilePath,
				Operations:     make([]FileAccess, 0),
				SecurityIssues: make([]SecurityAlert, 0),
			}
			fileMap[access.FilePath] = info
		}
		info.Operations = append(info.Operations, access)
	}

	// Associate security alerts
	for _, alert := range trace.SecurityAlerts {
		if info, exists := fileMap[alert.FilePath]; exists {
			info.SecurityIssues = append(info.SecurityIssues, alert)
		}
	}

	// Convert to list
	for _, info := range fileMap {
		details.FilesAccessed = append(details.FilesAccessed, *info)
	}

	return details
}

// ErrorDetails represents error details
type ErrorDetails struct {
	Errors      []ErrorRecord `json:"errors"`
	RetryChains []RetryChain  `json:"retry_chains"`
}

// RetryChain represents a retry chain
type RetryChain struct {
	OriginalCall       string                   `json:"original_call"`
	FailureReason      string                   `json:"failure_reason"`
	InvestigationSteps []map[string]interface{} `json:"investigation_steps"`
	Resolution         string                   `json:"resolution,omitempty"`
}

// FormatErrors generates error details
func (f *TraceFormatter) FormatErrors(trace *ExecutionTrace) *ErrorDetails {
	return &ErrorDetails{
		Errors:      trace.Errors,
		RetryChains: f.buildRetryChains(trace),
	}
}

// buildRetryChains builds retry chains
func (f *TraceFormatter) buildRetryChains(trace *ExecutionTrace) []RetryChain {
	// TODO: Implement retry chain analysis logic
	// Need to analyze subsequent tool calls after errors to determine if they are recovery operations
	return make([]RetryChain, 0)
}

// FormatJSON formats object as JSON
func (f *TraceFormatter) FormatJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
