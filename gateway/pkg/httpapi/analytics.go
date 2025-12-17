package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/textencoding"
)

// CorrelationSummaryResponse represents the JSON payload returned by the correlations endpoint.
type CorrelationSummaryResponse struct {
	Host                  string          `json:"host"`
	ResponseID            *string         `json:"response_id,omitempty"`
	ResponseTs            *time.Time      `json:"response_ts,omitempty"`
	StatusCode            *int32          `json:"status_code,omitempty"`
	Method                *string         `json:"method,omitempty"`
	URL                   *string         `json:"url,omitempty"`
	RootExecID            *string         `json:"root_exec_id,omitempty"`
	RootPID               *int64          `json:"root_pid,omitempty"`
	BestEventID           *string         `json:"best_event_id,omitempty"`
	BestEventExecID       *string         `json:"best_event_exec_id,omitempty"`
	EventRootExecID       *string         `json:"event_root_exec_id,omitempty"`
	EventRootPID          *int64          `json:"event_root_pid,omitempty"`
	BestEventComm         *string         `json:"best_event_comm,omitempty"`
	BestEventArgs         *string         `json:"best_event_args,omitempty"`
	BestTotalScore        *float64        `json:"best_total_score,omitempty"`
	BestCorrelationType   *string         `json:"best_correlation_type,omitempty"`
	BestGapMs             *float64        `json:"best_gap_ms,omitempty"`
	BestLineageScore      *float64        `json:"best_lineage_score,omitempty"`
	BestTemporalScore     *float64        `json:"best_temporal_score,omitempty"`
	BestArgumentScore     *float64        `json:"best_argument_score,omitempty"`
	BestArgumentMatchFlag *int32          `json:"best_argument_match_flag,omitempty"`
	SystemActions         json.RawMessage `json:"system_actions,omitempty"`
	Evidence              json.RawMessage `json:"evidence,omitempty"`
}

// HeuristicAlertResponse represents the JSON payload returned by the heuristic alerts endpoint.
type HeuristicAlertResponse struct {
	AlertID    string          `json:"alert_id"`
	AlertType  string          `json:"alert_type"`
	Host       string          `json:"host"`
	Severity   *string         `json:"severity,omitempty"`
	Score      *float64        `json:"score,omitempty"`
	StartTs    *time.Time      `json:"start_ts,omitempty"`
	EndTs      *time.Time      `json:"end_ts,omitempty"`
	RootExecID *string         `json:"root_exec_id,omitempty"`
	RootPID    *int64          `json:"root_pid,omitempty"`
	Details    json.RawMessage `json:"details,omitempty"`
	Reason     *string         `json:"reason,omitempty"`
}

// ProcessHTTPEventResponse represents the JSON payload returned by the HTTP events endpoint.
type ProcessHTTPEventResponse struct {
	Host       string          `json:"host"`
	HTTPID     *string         `json:"http_id,omitempty"`
	HTTPType   string          `json:"http_type"`
	Timestamp  *time.Time      `json:"timestamp,omitempty"`
	PID        *int32          `json:"pid,omitempty"`
	TID        *int32          `json:"tid,omitempty"`
	Method     *string         `json:"method,omitempty"`
	URL        *string         `json:"url,omitempty"`
	StatusCode *int32          `json:"status_code,omitempty"`
	Protocol   *string         `json:"protocol,omitempty"`
	Headers    json.RawMessage `json:"headers,omitempty"`
	Body       []byte          `json:"body,omitempty"`
	Truncated  *bool           `json:"truncated,omitempty"`
	ExecID     *string         `json:"exec_id,omitempty"`
	RootExecID *string         `json:"root_exec_id,omitempty"`
	RootPID    *int64          `json:"root_pid,omitempty"`
	Depth      *int32          `json:"depth,omitempty"`
	IsMcpHTTP  *bool           `json:"is_mcp_http,omitempty"`
}

// SecuritySemanticRecord represents a single semantic analysis row returned from the LLM security endpoint.
type SecuritySemanticRecord struct {
	ID              *string         `json:"id,omitempty"`
	AnalyzedAt      *time.Time      `json:"analyzed_at,omitempty"`
	RootExecID      *string         `json:"root_exec_id,omitempty"`
	ThreatLevel     *int32          `json:"threat_level,omitempty"`
	ThreatType      *string         `json:"threat_type,omitempty"`
	Confidence      *float64        `json:"confidence,omitempty"`
	Summary         *string         `json:"summary,omitempty"`
	Details         *string         `json:"details,omitempty"`
	Recommendations json.RawMessage `json:"recommendations,omitempty"`
	Evidence        json.RawMessage `json:"evidence,omitempty"`
}

// PromptInjectionRecord represents a single prompt injection row for the security endpoint.
type PromptInjectionRecord struct {
	RequestID  *string         `json:"request_id,omitempty"`
	Severity   *string         `json:"severity,omitempty"`
	Categories []string        `json:"categories,omitempty"`
	ObservedAt *time.Time      `json:"observed_at,omitempty"`
	Reason     *string         `json:"reason,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
}

// SecurityLLMAnalysisResponse bundles semantic and prompt analysis payloads.
type SecurityLLMAnalysisResponse struct {
	Semantic         []SecuritySemanticRecord `json:"semantic"`
	PromptInjections []PromptInjectionRecord  `json:"prompt_injections"`
}

// HTTPRequestDetailResponse exposes the stored request payload for prompt investigation.
type HTTPRequestDetailResponse struct {
	ID            *string         `json:"id,omitempty"`
	Host          string          `json:"host"`
	Timestamp     *time.Time      `json:"timestamp,omitempty"`
	PID           int32           `json:"pid"`
	TID           int32           `json:"tid"`
	UID           int32           `json:"uid"`
	GID           int32           `json:"gid"`
	Comm          string          `json:"comm"`
	Method        string          `json:"method"`
	ContentLength int64           `json:"content_length"`
	URL           string          `json:"url"`
	Protocol      string          `json:"protocol"`
	Headers       json.RawMessage `json:"headers,omitempty"`
	Body          []byte          `json:"body,omitempty"`
	Truncated     *bool           `json:"truncated,omitempty"`
}

// ProcessEventResponse represents a lifecycle event entry.
type ProcessEventResponse struct {
	Host         string     `json:"host"`
	ExecID       string     `json:"exec_id"`
	ParentExecID *string    `json:"parent_exec_id,omitempty"`
	PID          *int64     `json:"pid,omitempty"`
	PPID         *int64     `json:"ppid,omitempty"`
	RootExecID   *string    `json:"root_exec_id,omitempty"`
	RootPID      *int64     `json:"root_pid,omitempty"`
	Depth        *int32     `json:"depth,omitempty"`
	StartTs      *time.Time `json:"start_ts,omitempty"`
	EndTs        *time.Time `json:"end_ts,omitempty"`
	Comm         *string    `json:"comm,omitempty"`
	Args         *string    `json:"args,omitempty"`
	Cwd          *string    `json:"cwd,omitempty"`
}

// ProcessTreeNodeResponse describes a node in the process tree hierarchy.
type ProcessTreeNodeResponse struct {
	ExecID       *string                   `json:"exec_id,omitempty"`
	ParentExecID *string                   `json:"parent_exec_id,omitempty"`
	PID          *int64                    `json:"pid,omitempty"`
	PPID         *int64                    `json:"ppid,omitempty"`
	RootExecID   *string                   `json:"root_exec_id,omitempty"`
	RootPID      *int64                    `json:"root_pid,omitempty"`
	Depth        *int32                    `json:"depth,omitempty"`
	StartTs      *time.Time                `json:"start_ts,omitempty"`
	EndTs        *time.Time                `json:"end_ts,omitempty"`
	Comm         *string                   `json:"comm,omitempty"`
	Args         *string                   `json:"args,omitempty"`
	Cwd          *string                   `json:"cwd,omitempty"`
	Children     []ProcessTreeNodeResponse `json:"children,omitempty"`
}

// ProcessSummaryMeta captures aggregated metadata for a root process.
type ProcessSummaryMeta struct {
	ExecID     *string    `json:"exec_id,omitempty"`
	Comm       *string    `json:"comm,omitempty"`
	Args       *string    `json:"args,omitempty"`
	FirstSeen  *time.Time `json:"first_seen,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	EventCount int64      `json:"event_count"`
}

// ProcessSummaryResponse aggregates meta information and alerts for a root PID.
type ProcessSummaryResponse struct {
	Meta   ProcessSummaryMeta       `json:"meta"`
	Alerts []HeuristicAlertResponse `json:"alerts"`
}

// AgentRunResponse captures the lifecycle metadata for a single agent run.
type AgentRunResponse struct {
	ID         string     `json:"id"`
	Host       string     `json:"host"`
	RootExecID *string    `json:"root_exec_id,omitempty"`
	RootPID    *int64     `json:"root_pid,omitempty"`
	Provider   *string    `json:"provider,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
}

// TraceGraphResponse bundles the agent run along with all trace nodes for rendering.
type TraceGraphResponse struct {
	AgentRun AgentRunResponse    `json:"agent_run"`
	Traces   []TraceNodeResponse `json:"traces"`
}

// TraceNodeResponse represents a single trace row enriched with contextual payloads.
type TraceNodeResponse struct {
	ID              string                        `json:"id"`
	AgentRunID      string                        `json:"agent_run_id"`
	ParentTraceID   *string                       `json:"parent_trace_id,omitempty"`
	TraceType       string                        `json:"trace_type"`
	Phase           string                        `json:"phase"`
	SourceTable     *string                       `json:"source_table,omitempty"`
	SourceID        *string                       `json:"source_id,omitempty"`
	ExternalID      *string                       `json:"external_id,omitempty"`
	Model           *string                       `json:"model,omitempty"`
	ModelVersion    *string                       `json:"model_version,omitempty"`
	StartedAt       *time.Time                    `json:"started_at,omitempty"`
	EndedAt         *time.Time                    `json:"ended_at,omitempty"`
	PromptPreview   *string                       `json:"prompt_preview,omitempty"`
	ResponsePreview *string                       `json:"response_preview,omitempty"`
	ResourceUsage   map[string]ResourceUsageEntry `json:"resource_usage,omitempty"`
	LLM             *LLMTraceDetails              `json:"llm,omitempty"`
	Tool            *ToolTraceDetails             `json:"tool,omitempty"`
	MCP             *MCPTraceDetails              `json:"mcp,omitempty"`
}

// ResourceUsageEntry exposes numeric resource metrics keyed by trace metric name.
type ResourceUsageEntry struct {
	Value *float64 `json:"value,omitempty"`
	Unit  *string  `json:"unit,omitempty"`
}

// LLMTraceDetails includes normalized prompt/response payloads for llm_call traces.
type LLMTraceDetails struct {
	ResponseKey  string          `json:"response_key"`
	Provider     *string         `json:"provider,omitempty"`
	Model        *string         `json:"model,omitempty"`
	ModelVersion *string         `json:"model_version,omitempty"`
	Prompt       json.RawMessage `json:"prompt,omitempty"`
	Response     json.RawMessage `json:"response,omitempty"`
	Usage        json.RawMessage `json:"usage,omitempty"`
	Status       *string         `json:"status,omitempty"`
	RawRequest   *string         `json:"raw_request,omitempty"`
	RawResponse  *string         `json:"raw_response,omitempty"`
	ExecID       *string         `json:"exec_id,omitempty"`
	RootExecID   *string         `json:"root_exec_id,omitempty"`
}

// ToolTraceDetails captures tool call arguments associated with tool_use traces.
type ToolTraceDetails struct {
	ToolCallID  string          `json:"tool_call_id"`
	ResponseKey string          `json:"response_key"`
	Name        *string         `json:"name,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}

// MCPTraceDetails aggregates MCP JSON-RPC messages for mcp_call traces.
type MCPTraceDetails struct {
	CorrID  string       `json:"corr_id"`
	Method  *string      `json:"method,omitempty"`
	Server  *string      `json:"server,omitempty"`
	Tool    *string      `json:"tool,omitempty"`
	Entries []MCPMessage `json:"entries,omitempty"`
}

// MCPMessage records a single MCP request/response/notification payload.
type MCPMessage struct {
	MessageType string          `json:"message_type"`
	Timestamp   *time.Time      `json:"timestamp,omitempty"`
	Server      *string         `json:"server,omitempty"`
	Params      json.RawMessage `json:"params,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       json.RawMessage `json:"error,omitempty"`
}

type treeNode struct {
	data      ProcessTreeNodeResponse
	parentKey string
	rootKey   string
	children  []*treeNode
}

type analyticsHandlers struct {
	queries *sqlc.Queries
}

func registerAnalyticsRoutes(group *gin.RouterGroup, queries *sqlc.Queries) {
	h := analyticsHandlers{queries: queries}
	group.GET("/correlation_summaries", h.getCorrelations)
	group.GET("/hosts", h.listHosts)
	group.GET("/heuristic_alerts", h.getHeuristicAlerts)
	group.GET("/process_http_events", h.getHTTPEvents)
	group.GET("/security_llm_analysis", h.getSecurityLLMAnalysis)
	group.GET("/prompt_injections/:request_id", h.getPromptInjectionDetails)
	group.GET("/process_events", h.getProcessEvents)
	group.GET("/process_tree", h.getProcessTree)
	group.GET("/process_summary/:root_pid", h.getProcessSummary)
	group.GET("/agent_runs", h.getAgentRuns)
	group.GET("/agent_runs/:agent_run_id/traces", h.getTraceGraph)
}

// getCorrelations godoc
// @Summary      List correlation summaries
// @Description  Returns correlation summaries for a host since the provided timestamp.
// @Tags         analytics
// @Produce      json
// @Param        host  query     string true  "Target host"
// @Param        since query     string true  "RFC3339 timestamp lower bound"
// @Param        until query     string false "RFC3339 timestamp upper bound (defaults to now)"
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   CorrelationSummaryResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/correlation_summaries [get]
func (h analyticsHandlers) getCorrelations(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}
	rows, err := h.queries.ListCorrelationsByHostRange(c.Request.Context(), sqlc.ListCorrelationsByHostRangeParams{
		Host:  host,
		Since: pgtype.Timestamptz{Time: since, Valid: true},
		Until: pgtype.Timestamptz{Time: until, Valid: true},
		Limit: limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]CorrelationSummaryResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, CorrelationSummaryResponse{
			Host:                  row.Host,
			ResponseID:            uuidPtrFromUUID(row.ResponseID),
			ResponseTs:            timePtrFromTimestamptz(row.ResponseTs),
			StatusCode:            int32PtrFromInt4(row.StatusCode),
			Method:                stringPtrFromText(row.Method),
			URL:                   stringPtrFromText(row.Url),
			RootExecID:            stringPtrFromText(row.RootExecID),
			RootPID:               int64PtrFromInt8(row.RootPid),
			BestEventID:           uuidPtrFromUUID(row.BestEventID),
			BestEventExecID:       stringPtrFromText(row.BestEventExecID),
			EventRootExecID:       stringPtrFromText(row.EventRootExecID),
			EventRootPID:          int64PtrFromInt8(row.EventRootPid),
			BestEventComm:         stringPtrFromText(row.BestEventComm),
			BestEventArgs:         stringPtrFromText(row.BestEventArgs),
			BestTotalScore:        float64PtrFromNumeric(row.BestTotalScore),
			BestCorrelationType:   stringPtrFromText(row.BestCorrelationType),
			BestGapMs:             float64PtrFromFloat8(row.BestGapMs),
			BestLineageScore:      float64PtrFromFloat8(row.BestLineageScore),
			BestTemporalScore:     float64PtrFromFloat8(row.BestTemporalScore),
			BestArgumentScore:     float64PtrFromFloat8(row.BestArgumentScore),
			BestArgumentMatchFlag: int32PtrFromInt4(row.BestArgumentMatchFlag),
			SystemActions:         jsonInterface(row.SystemActions),
			Evidence:              jsonInterface(row.Evidence),
		})
	}

	c.JSON(http.StatusOK, resp)
}

// getHeuristicAlerts godoc
// @Summary      List heuristic alerts
// @Description  Returns heuristic alerts for a host since the provided timestamp.
// @Tags         analytics
// @Produce      json
// @Param        host  query     string true  "Target host"
// @Param        since query     string true  "RFC3339 timestamp lower bound"
// @Param        until query     string false "RFC3339 timestamp upper bound (defaults to now)"
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   HeuristicAlertResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/heuristic_alerts [get]
func (h analyticsHandlers) getHeuristicAlerts(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListHeuristicAlertsByHostRange(c.Request.Context(), sqlc.ListHeuristicAlertsByHostRangeParams{
		Host:  host,
		Since: pgtype.Timestamptz{Time: since, Valid: true},
		Until: pgtype.Timestamptz{Time: until, Valid: true},
		Limit: limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]HeuristicAlertResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, convertHeuristicAlertWithDetails(row, h.enrichPromptInjectionAlertDetails(c.Request.Context(), row)))
	}

	c.JSON(http.StatusOK, resp)
}

// listHosts godoc
// @Summary      List available hosts
// @Description  Returns distinct hosts observed in process telemetry.
// @Tags         analytics
// @Produce      json
// @Param        limit query     int false "Maximum number of hosts" minimum(1) maximum(1000)
// @Success      200   {array}   string
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/hosts [get]
func (h analyticsHandlers) listHosts(c *gin.Context) {
	limit, ok := parseLimitQuery(c, "limit", 200, 1, 1000)
	if !ok {
		return
	}

	hosts, err := h.queries.ListHosts(c.Request.Context(), limit)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	c.JSON(http.StatusOK, hosts)
}

// getHTTPEvents godoc
// @Summary      List process HTTP events
// @Description  Returns process HTTP events for a host since the provided timestamp.
// @Tags         analytics
// @Produce      json
// @Param        host  query     string true  "Target host"
// @Param        since query     string true  "RFC3339 timestamp lower bound"
// @Param        until query     string false "RFC3339 timestamp upper bound (defaults to now)"
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   ProcessHTTPEventResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/process_http_events [get]
func (h analyticsHandlers) getHTTPEvents(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListProcessHTTPEventsByHostRange(c.Request.Context(), sqlc.ListProcessHTTPEventsByHostRangeParams{
		Host:  host,
		Since: pgtype.Timestamptz{Time: since, Valid: true},
		Until: pgtype.Timestamptz{Time: until, Valid: true},
		Limit: limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]ProcessHTTPEventResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, ProcessHTTPEventResponse{
			Host:       row.Host,
			HTTPID:     uuidPtrFromUUID(row.HttpID),
			HTTPType:   row.HttpType,
			Timestamp:  timePtrFromTimestamptz(row.Timestamp),
			PID:        int32PtrFromInt4(row.Pid),
			TID:        int32PtrFromInt4(row.Tid),
			Method:     stringPtrFromText(row.Method),
			URL:        stringPtrFromText(row.Url),
			StatusCode: int32PtrFromInt4(row.StatusCode),
			Protocol:   stringPtrFromText(row.Protocol),
			Headers:    jsonInterface(row.Headers),
			Body:       row.Body,
			Truncated:  boolPtrFromBool(row.Truncated),
			ExecID:     stringPtrFromText(row.ExecID),
			RootExecID: stringPtrFromText(row.RootExecID),
			RootPID:    int64PtrFromInt8(row.RootPid),
			Depth:      int32PtrFromInt4(row.Depth),
			IsMcpHTTP:  boolPtrFromBool(row.IsMcpHttp),
		})
	}

	c.JSON(http.StatusOK, resp)
}

// getSecurityLLMAnalysis godoc
// @Summary      List security semantic and prompt injection analysis
// @Description  Returns LLM security analysis records and prompt injection summaries for a host.
// @Tags         analytics
// @Produce      json
// @Param        host            query     string true  "Target host"
// @Param        semantic_limit  query     int    false "Maximum semantic records" minimum(1) maximum(500)
// @Param        prompt_limit    query     int    false "Maximum prompt injection records" minimum(1) maximum(500)
// @Success      200             {object}  SecurityLLMAnalysisResponse
// @Failure      400             {object}  ErrorResponse
// @Failure      500             {object}  ErrorResponse
// @Router       /api/v1/analysis/security_llm_analysis [get]
func (h analyticsHandlers) getSecurityLLMAnalysis(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "host is required", nil)
		return
	}

	semanticLimit, ok := parseLimitQuery(c, "semantic_limit", 20, 1, 500)
	if !ok {
		return
	}

	promptLimit, ok := parseLimitQuery(c, "prompt_limit", 20, 1, 500)
	if !ok {
		return
	}

	ctx := c.Request.Context()

	semanticRows, err := h.queries.ListSecurityAnalysisByHost(ctx, sqlc.ListSecurityAnalysisByHostParams{
		Host:  textParam(host),
		Limit: semanticLimit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	promptRows, err := h.queries.ListPromptInjectionsByHost(ctx, sqlc.ListPromptInjectionsByHostParams{
		Host:  host,
		Limit: promptLimit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	semantic := make([]SecuritySemanticRecord, 0, len(semanticRows))
	for _, row := range semanticRows {
		semantic = append(semantic, SecuritySemanticRecord{
			ID:              uuidPtrFromUUID(row.ID),
			AnalyzedAt:      timePtrFromTimestamptz(row.AnalyzedAt),
			RootExecID:      stringPtrFromText(row.RootExecID),
			ThreatLevel:     int32PtrFromInt4(row.ThreatLevel),
			ThreatType:      stringPtrFromText(row.ThreatType),
			Confidence:      float64PtrFromFloat8(row.Confidence),
			Summary:         stringPtrFromText(row.Summary),
			Details:         stringPtrFromText(row.Details),
			Recommendations: jsonInterface(row.Recommendations),
			Evidence:        jsonInterface(row.Evidence),
		})
	}

	prompts := make([]PromptInjectionRecord, 0, len(promptRows))
	for _, row := range promptRows {
		evidence := extractPromptEvidence(row.Metadata)
		prompts = append(prompts, PromptInjectionRecord{
			RequestID:  uuidPtrFromUUID(row.RequestID),
			Severity:   stringPtr(row.SeverityLevel),
			Categories: parseCategories(row.Categories),
			ObservedAt: timePtrFromTimestamptz(row.ObservedAt),
			Reason:     stringPtrFromText(row.Reason),
			Evidence:   evidence,
		})
	}

	c.JSON(http.StatusOK, SecurityLLMAnalysisResponse{
		Semantic:         semantic,
		PromptInjections: prompts,
	})
}

func extractPromptEvidence(metadata []byte) json.RawMessage {
	if len(metadata) == 0 {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(metadata, &obj); err != nil {
		return nil
	}
	evidence, ok := obj["evidence"]
	if !ok || evidence == nil {
		return nil
	}
	switch evidence.(type) {
	case []any, map[string]any, string, float64, bool:
		// Marshal it back to JSON raw message.
		if b, err := json.Marshal(evidence); err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}

// getPromptInjectionDetails godoc
// @Summary      Get stored HTTP request for a prompt injection
// @Description  Returns the HTTP request payload associated with a prompt injection request ID.
// @Tags         analytics
// @Produce      json
// @Param        host         query     string true  "Target host"
// @Param        request_id   path      string true  "Prompt injection request UUID"
// @Success      200          {object}  HTTPRequestDetailResponse
// @Failure      400          {object}  ErrorResponse
// @Failure      404          {object}  ErrorResponse
// @Failure      500          {object}  ErrorResponse
// @Router       /api/v1/analysis/prompt_injections/{request_id} [get]
func (h analyticsHandlers) getPromptInjectionDetails(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "host is required", nil)
		return
	}

	reqIDStr := strings.TrimSpace(c.Param("request_id"))
	if reqIDStr == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "request_id is required", nil)
		return
	}

	reqUUID, err := uuid.Parse(reqIDStr)
	if err != nil {
		respondError(c, http.StatusBadRequest, "validation_failed", "request_id must be a UUID", nil)
		return
	}

	idParam := pgtype.UUID{Bytes: reqUUID, Valid: true}

	row, err := h.queries.GetHTTPRequestByHostAndID(c.Request.Context(), sqlc.GetHTTPRequestByHostAndIDParams{
		Host: host,
		ID:   idParam,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, http.StatusNotFound, "not_found", "request not found", nil)
			return
		}
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := HTTPRequestDetailResponse{
		ID:            uuidPtrFromUUID(row.ID),
		Host:          row.Host,
		Timestamp:     timePtrFromTimestamptz(row.Timestamp),
		PID:           row.Pid,
		TID:           row.Tid,
		UID:           row.Uid,
		GID:           row.Gid,
		Comm:          row.Comm,
		Method:        row.Method,
		ContentLength: int64ValueFromInt8(row.ContentLength),
		URL:           row.Url,
		Protocol:      row.Protocol,
		Headers:       jsonInterface(row.Headers),
		Body:          row.Body,
		Truncated:     boolPtrValue(row.Truncated),
	}

	c.JSON(http.StatusOK, resp)
}

// getProcessEvents godoc
// @Summary      List process lifecycle events
// @Description  Returns individual lifecycle events for a host since the provided timestamp.
// @Tags         analytics
// @Produce      json
// @Param        host  query     string true  "Target host"
// @Param        since query     string true  "RFC3339 timestamp lower bound"
// @Param        until query     string false "RFC3339 timestamp upper bound (defaults to now)"
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   ProcessEventResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/process_events [get]
func (h analyticsHandlers) getProcessEvents(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListProcessEventsByHostRange(c.Request.Context(), sqlc.ListProcessEventsByHostRangeParams{
		Host:  host,
		Since: pgtype.Timestamptz{Time: since, Valid: true},
		Until: pgtype.Timestamptz{Time: until, Valid: true},
		Limit: limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	events := make([]ProcessEventResponse, 0, len(rows))
	for _, row := range rows {
		parent := stringPtrFromText(row.PExecID)
		events = append(events, ProcessEventResponse{
			Host:         row.Host,
			ExecID:       row.ExecID,
			ParentExecID: parent,
			PID:          int64PtrFromInt8(row.Pid),
			PPID:         int64PtrFromInt8(row.Ppid),
			RootExecID:   stringPtrFromText(row.RootExecID),
			RootPID:      int64PtrFromInt8(row.RootPid),
			Depth:        int32PtrFromInt4(row.Depth),
			StartTs:      timePtrFromTimestamptz(row.StartTs),
			EndTs:        timePtrFromTimestamptz(row.EndTs),
			Comm:         stringPtrFromText(row.Comm),
			Args:         stringPtrFromText(row.Args),
			Cwd:          stringPtrFromText(row.Cwd),
		})
	}

	c.JSON(http.StatusOK, events)
}

// getProcessTree godoc
// @Summary      List process tree
// @Description  Returns a hierarchical process tree for the most recent roots on a host.
// @Tags         analytics
// @Produce      json
// @Param        host        query     string true  "Target host"
// @Param        root_pid    query     string false "Specific root PID to expand"
// @Param        root_exec_id query    string false "Specific root exec id to expand"
// @Param        since       query     string false "RFC3339 timestamp lower bound"
// @Param        until       query     string false "RFC3339 timestamp upper bound"
// @Param        root_limit  query     int    false "Maximum unique roots" minimum(1) maximum(2000)
// @Param        node_limit  query     int    false "Maximum nodes returned" minimum(1) maximum(2000)
// @Success      200         {array}   ProcessTreeNodeResponse
// @Failure      400         {object}  ErrorResponse
// @Failure      500         {object}  ErrorResponse
// @Router       /api/v1/analysis/process_tree [get]
func (h analyticsHandlers) getProcessTree(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "host is required", nil)
		return
	}

	rootLimit, ok := parseLimitQuery(c, "root_limit", 5, 1, 2000)
	if !ok {
		return
	}

	nodeLimit, ok := parseLimitQuery(c, "node_limit", 500, 1, 2000)
	if !ok {
		return
	}

	rootExecFilter := strings.TrimSpace(c.Query("root_exec_id"))

	sinceBound, untilBound, ok := parseOptionalBounds(c)
	if !ok {
		return
	}

	var (
		rootIDs         []int64
		includeNullRoot bool
		rootOrder       []string
	)

	if rootPIDStr := strings.TrimSpace(c.Query("root_pid")); rootPIDStr != "" {
		pid, err := strconv.ParseInt(rootPIDStr, 10, 64)
		if err != nil {
			respondError(c, http.StatusBadRequest, "validation_failed", "root_pid must be an integer", nil)
			return
		}
		rootIDs = append(rootIDs, pid)
		rootOrder = append(rootOrder, rootKeyFromValues(&pid, nil))
	} else {
		roots, err := h.queries.ListProcessTreeRootsByHost(c.Request.Context(), sqlc.ListProcessTreeRootsByHostParams{
			Host:  host,
			Limit: rootLimit,
			Since: sinceBound,
			Until: untilBound,
		})
		if err != nil {
			respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
			return
		}
		for _, root := range roots {
			if root.Valid {
				rootIDs = append(rootIDs, root.Int64)
				pid := root.Int64
				rootOrder = append(rootOrder, rootKeyFromValues(&pid, nil))
			} else {
				includeNullRoot = true
				rootOrder = append(rootOrder, rootKeyFromValues(nil, nil))
			}
		}
	}

	if rootExecFilter == "" && len(rootIDs) == 0 && !includeNullRoot {
		c.JSON(http.StatusOK, []ProcessTreeNodeResponse{})
		return
	}

	if rootIDs == nil {
		rootIDs = []int64{}
	}

	nodesRows, err := h.queries.ListProcessTreeNodesByRoots(c.Request.Context(), sqlc.ListProcessTreeNodesByRootsParams{
		Host:        host,
		RootPids:    rootIDs,
		IncludeNull: includeNullRoot,
		RootExecID:  rootExecFilter,
		Since:       sinceBound,
		Until:       untilBound,
		Limit:       nodeLimit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	nodes := make(map[string]*treeNode, len(nodesRows))
	ordered := make([]*treeNode, 0, len(nodesRows))
	rootsByKey := make(map[string][]*treeNode)
	rootOrderSet := make(map[string]struct{}, len(rootOrder))
	for _, key := range rootOrder {
		rootOrderSet[key] = struct{}{}
	}

	extraOrder := make([]string, 0)
	extraOrderSet := make(map[string]struct{})

	for _, row := range nodesRows {
		rootExec := stringPtrFromText(row.RootExecID)

		execID := row.ExecID
		node := &treeNode{
			data: ProcessTreeNodeResponse{
				ExecID:       &execID,
				ParentExecID: stringPtrFromText(row.PExecID),
				PID:          int64PtrFromInt8(row.Pid),
				PPID:         int64PtrFromInt8(row.Ppid),
				RootExecID:   rootExec,
				RootPID:      int64PtrFromInt8(row.RootPid),
				Depth:        int32PtrFromInt4(row.Depth),
				StartTs:      timePtrFromTimestamptz(row.StartTs),
				EndTs:        timePtrFromTimestamptz(row.EndTs),
				Comm:         stringPtrFromText(row.Comm),
				Args:         stringPtrFromText(row.Args),
				Cwd:          stringPtrFromText(row.Cwd),
			},
		}

		node.parentKey = zeroIfNil(node.data.ParentExecID)
		node.rootKey = rootKeyFromValues(node.data.RootPID, node.data.RootExecID)

		nodes[row.ExecID] = node
		ordered = append(ordered, node)

		if _, ok := rootsByKey[node.rootKey]; !ok {
			rootsByKey[node.rootKey] = nil
			if _, exists := rootOrderSet[node.rootKey]; !exists {
				if _, seen := extraOrderSet[node.rootKey]; !seen {
					extraOrder = append(extraOrder, node.rootKey)
					extraOrderSet[node.rootKey] = struct{}{}
				}
			}
		}
	}

	if len(ordered) == 0 {
		c.JSON(http.StatusOK, []ProcessTreeNodeResponse{})
		return
	}

	for _, node := range ordered {
		if node.parentKey != "" {
			if parent, ok := nodes[node.parentKey]; ok {
				parent.children = append(parent.children, node)
				continue
			}
		}
		rootsByKey[node.rootKey] = append(rootsByKey[node.rootKey], node)
	}

	order := append([]string{}, rootOrder...)
	order = append(order, extraOrder...)

	result := make([]ProcessTreeNodeResponse, 0)
	seen := make(map[string]struct{})
	for _, key := range order {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		nodesForRoot := rootsByKey[key]
		for _, node := range nodesForRoot {
			result = append(result, buildProcessTree(node))
		}
		delete(rootsByKey, key)
	}

	for _, nodesForRoot := range rootsByKey {
		for _, node := range nodesForRoot {
			result = append(result, buildProcessTree(node))
		}
	}

	c.JSON(http.StatusOK, result)
}

// getProcessSummary godoc
// @Summary      Summarize a process root
// @Description  Returns aggregated metadata and recent alerts for a specific process root.
// @Tags         analytics
// @Produce      json
// @Param        host          query     string true  "Target host"
// @Param        root_pid      path      string true  "Root PID"
// @Param        root_exec_id  query     string false "Root exec ID"
// @Param        alerts_limit  query     int    false "Maximum alerts" minimum(1) maximum(1000)
// @Success      200           {object}  ProcessSummaryResponse
// @Failure      400           {object}  ErrorResponse
// @Failure      404           {object}  ErrorResponse
// @Failure      500           {object}  ErrorResponse
// @Router       /api/v1/analysis/process_summary/{root_pid} [get]
func (h analyticsHandlers) getProcessSummary(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "host is required", nil)
		return
	}

	rootPIDStr := strings.TrimSpace(c.Param("root_pid"))
	rootPID, err := strconv.ParseInt(rootPIDStr, 10, 64)
	if err != nil {
		respondError(c, http.StatusBadRequest, "validation_failed", "root_pid must be an integer", nil)
		return
	}

	alertsLimit, ok := parseLimitQuery(c, "alerts_limit", 10, 1, 1000)
	if !ok {
		return
	}

	rootExec := strings.TrimSpace(c.Query("root_exec_id"))

	ctx := c.Request.Context()
	meta, err := h.queries.GetProcessMetaByHostRoot(ctx, sqlc.GetProcessMetaByHostRootParams{
		Host:    host,
		RootPid: pgtype.Int8{Int64: rootPID, Valid: true},
		Column3: rootExec,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, http.StatusNotFound, "not_found", "process root not found", nil)
			return
		}
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	if meta.EventCount == 0 {
		respondError(c, http.StatusNotFound, "not_found", "process root not found", nil)
		return
	}

	alerts, err := h.queries.ListHeuristicAlertsByRoot(ctx, sqlc.ListHeuristicAlertsByRootParams{
		Host:    host,
		RootPid: pgtype.Int8{Int64: rootPID, Valid: true},
		Column3: rootExec,
		Limit:   alertsLimit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	alertResponses := make([]HeuristicAlertResponse, 0, len(alerts))
	for _, alert := range alerts {
		alertResponses = append(alertResponses, convertHeuristicAlertWithDetails(alert, h.enrichPromptInjectionAlertDetails(ctx, alert)))
	}

	resp := ProcessSummaryResponse{
		Meta: ProcessSummaryMeta{
			ExecID:     stringPtrIfNotEmpty(meta.ExecID),
			Comm:       stringPtrIfNotEmpty(meta.Comm),
			Args:       stringPtrIfNotEmpty(meta.Args),
			FirstSeen:  timePtrFromTimestamptz(meta.FirstSeen),
			LastSeen:   timePtrFromTimestamptz(meta.LastSeen),
			EventCount: meta.EventCount,
		},
		Alerts: alertResponses,
	}

	c.JSON(http.StatusOK, resp)
}

// getAgentRuns godoc
// @Summary      List agent runs
// @Description  Returns agent runs detected for a host within the requested window.
// @Tags         analytics
// @Produce      json
// @Param        host  query     string true  "Target host"
// @Param        since query     string true  "RFC3339 timestamp lower bound"
// @Param        until query     string false "RFC3339 timestamp upper bound (defaults to now)"
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   AgentRunResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/agent_runs [get]
func (h analyticsHandlers) getAgentRuns(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListAgentRunsByHostRange(c.Request.Context(), sqlc.ListAgentRunsByHostRangeParams{
		Host:  host,
		Until: pgtype.Timestamptz{Time: until, Valid: true},
		Since: pgtype.Timestamptz{Time: since, Valid: true},
		Limit: limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]AgentRunResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, convertAgentRun(row))
	}

	c.JSON(http.StatusOK, resp)
}

// getTraceGraph godoc
// @Summary      Retrieve traces for an agent run
// @Description  Returns trace nodes plus contextual payloads for a specific agent run.
// @Tags         analytics
// @Produce      json
// @Param        host          query string true  "Target host"
// @Param        agent_run_id path  string true  "Agent run ID"
// @Success      200   {object} TraceGraphResponse
// @Failure      400   {object} ErrorResponse
// @Failure      404   {object} ErrorResponse
// @Failure      500   {object} ErrorResponse
// @Router       /api/v1/analysis/agent_runs/{agent_run_id}/traces [get]
func (h analyticsHandlers) getTraceGraph(c *gin.Context) {
	host := strings.TrimSpace(c.Query("host"))
	if host == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "host is required", nil)
		return
	}

	agentRunParam := strings.TrimSpace(c.Param("agent_run_id"))
	if agentRunParam == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "agent_run_id is required", nil)
		return
	}
	agentRunUUID, err := uuid.Parse(agentRunParam)
	if err != nil {
		respondError(c, http.StatusBadRequest, "validation_failed", "agent_run_id must be a valid UUID", nil)
		return
	}
	runID := pgtype.UUID{Bytes: agentRunUUID, Valid: true}

	ctx := c.Request.Context()
	run, err := h.queries.GetAgentRunByID(ctx, runID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, http.StatusNotFound, "not_found", "agent run not found", nil)
			return
		}
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	if !strings.EqualFold(run.Host, host) {
		respondError(c, http.StatusNotFound, "not_found", "agent run not found", nil)
		return
	}

	traces, err := h.queries.ListTracesByAgentRun(ctx, runID)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	traceResponses, err := h.buildTraceResponses(ctx, host, traces)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	c.JSON(http.StatusOK, TraceGraphResponse{
		AgentRun: convertAgentRun(run),
		Traces:   traceResponses,
	})
}

func (h analyticsHandlers) buildTraceResponses(ctx context.Context, host string, traces []sqlc.Trace) ([]TraceNodeResponse, error) {
	if len(traces) == 0 {
		return []TraceNodeResponse{}, nil
	}

	traceIDs := make([]pgtype.UUID, 0, len(traces))
	llmKeys := make([]string, 0, len(traces))
	toolIDs := make([]string, 0, len(traces))
	mcpIDs := make([]string, 0, len(traces))
	llmSeen := make(map[string]struct{})
	toolSeen := make(map[string]struct{})
	mcpSeen := make(map[string]struct{})

	for _, trace := range traces {
		if trace.ID.Valid {
			traceIDs = append(traceIDs, trace.ID)
		}
		extID := ""
		if trace.ExternalID.Valid {
			extID = strings.TrimSpace(trace.ExternalID.String)
		}
		if extID == "" {
			continue
		}
		switch trace.TraceType {
		case "llm_call":
			if _, ok := llmSeen[extID]; !ok {
				llmSeen[extID] = struct{}{}
				llmKeys = append(llmKeys, extID)
			}
		case "tool_use":
			if _, ok := toolSeen[extID]; !ok {
				toolSeen[extID] = struct{}{}
				toolIDs = append(toolIDs, extID)
			}
		case "mcp_call":
			if _, ok := mcpSeen[extID]; !ok {
				mcpSeen[extID] = struct{}{}
				mcpIDs = append(mcpIDs, extID)
			}
		}
	}

	usageByTrace := make(map[string]map[string]ResourceUsageEntry)
	if len(traceIDs) > 0 {
		usageRows, err := h.queries.ListResourceUsageByTraceIDs(ctx, traceIDs)
		if err != nil {
			return nil, err
		}
		for _, row := range usageRows {
			traceID := uuidStringFromUUID(row.TraceID)
			if traceID == "" {
				continue
			}
			metric := strings.TrimSpace(row.Metric)
			if metric == "" {
				continue
			}
			value := float64PtrFromNumeric(row.Value)
			unit := stringPtrFromText(row.Unit)
			if value == nil && unit == nil {
				continue
			}
			if _, ok := usageByTrace[traceID]; !ok {
				usageByTrace[traceID] = make(map[string]ResourceUsageEntry)
			}
			usageByTrace[traceID][metric] = ResourceUsageEntry{Value: value, Unit: unit}
		}
	}

	llmContext := make(map[string]*LLMTraceDetails)
	if len(llmKeys) > 0 {
		rows, err := h.queries.ListLLMEventsByResponseKeys(ctx, sqlc.ListLLMEventsByResponseKeysParams{
			Host:    host,
			Column2: llmKeys,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if !row.ResponseKey.Valid {
				continue
			}
			key := strings.TrimSpace(row.ResponseKey.String)
			if key == "" {
				continue
			}
			llmContext[key] = &LLMTraceDetails{
				ResponseKey:  key,
				Provider:     stringPtrFromText(row.Provider),
				Model:        stringPtrFromText(row.Model),
				ModelVersion: stringPtrFromText(row.ModelVersion),
				Prompt:       jsonInterface(row.Prompt),
				Response:     jsonInterface(row.Response),
				Usage:        jsonInterface(row.Usage),
				Status:       stringPtrFromText(row.Status),
				RawRequest:   stringPtrFromText(row.RawRequest),
				RawResponse:  stringPtrFromText(row.RawResponse),
				ExecID:       stringPtrFromText(row.ExecID),
				RootExecID:   stringPtrFromText(row.RootExecID),
			}
		}
	}

	toolContext := make(map[string]*ToolTraceDetails)
	if len(toolIDs) > 0 {
		rows, err := h.queries.ListToolCallsByIDs(ctx, sqlc.ListToolCallsByIDsParams{
			Host:    host,
			Column2: toolIDs,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			id := strings.TrimSpace(row.ToolCallID)
			if id == "" {
				continue
			}
			respKey := strings.TrimSpace(row.ResponseKey)
			toolContext[id] = &ToolTraceDetails{
				ToolCallID:  id,
				ResponseKey: respKey,
				Name:        stringPtrFromText(row.Name),
				Arguments:   jsonInterface(row.Arguments),
			}
		}
	}

	mcpContext := make(map[string]*MCPTraceDetails)
	if len(mcpIDs) > 0 {
		rows, err := h.queries.ListMcpEventsByCorrIDs(ctx, sqlc.ListMcpEventsByCorrIDsParams{
			Host:    host,
			Column2: mcpIDs,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			corr := strings.TrimSpace(stringFromAny(row.CorrID))
			if corr == "" {
				continue
			}
			method := strings.TrimSpace(stringFromAny(row.Method))
			server := strings.TrimSpace(stringFromAny(row.Server))
			tool := strings.TrimSpace(stringFromAny(row.Tool))
			detail, ok := mcpContext[corr]
			if !ok {
				detail = &MCPTraceDetails{
					CorrID: corr,
					Method: stringPtrIfNotEmpty(method),
					Server: stringPtrIfNotEmpty(server),
					Tool:   stringPtrIfNotEmpty(tool),
				}
				mcpContext[corr] = detail
			} else {
				if detail.Method == nil {
					detail.Method = stringPtrIfNotEmpty(method)
				}
				// Keep the first server seen (usually from request which has method)
				if detail.Server == nil {
					detail.Server = stringPtrIfNotEmpty(server)
				}
				if detail.Tool == nil {
					detail.Tool = stringPtrIfNotEmpty(tool)
				}
			}
			detail.Entries = append(detail.Entries, MCPMessage{
				MessageType: row.MessageType,
				Timestamp:   timePtrFromTimestamptz(row.Timestamp),
				Server:      stringPtrIfNotEmpty(server),
				Params:      jsonFromAny(row.Params),
				Result:      jsonFromAny(row.Result),
				Error:       jsonFromAny(row.Error),
			})
		}
	}

	responses := make([]TraceNodeResponse, 0, len(traces))
	for _, trace := range traces {
		traceID := uuidStringFromUUID(trace.ID)
		if traceID == "" {
			continue
		}
		resp := TraceNodeResponse{
			ID:            traceID,
			AgentRunID:    uuidStringFromUUID(trace.AgentRunID),
			ParentTraceID: uuidPtrFromUUID(trace.ParentTraceID),
			TraceType:     trace.TraceType,
			Phase:         trace.Phase,
			SourceTable:   stringPtrFromText(trace.SourceTable),
			SourceID:      uuidPtrFromUUID(trace.SourceID),
			ExternalID:    stringPtrFromText(trace.ExternalID),
			Model:         stringPtrFromText(trace.Model),
			ModelVersion:  stringPtrFromText(trace.ModelVersion),
			StartedAt:     timePtrFromTimestamptz(trace.StartedAt),
			EndedAt:       timePtrFromTimestamptz(trace.EndedAt),
		}
		if usage, ok := usageByTrace[traceID]; ok {
			resp.ResourceUsage = usage
		}
		extID := zeroIfNil(resp.ExternalID)
		switch trace.TraceType {
		case "llm_call":
			if ctx, ok := llmContext[extID]; ok {
				resp.LLM = ctx
				resp.PromptPreview = previewFromJSON(ctx.Prompt, 200)
				resp.ResponsePreview = previewFromJSON(ctx.Response, 200)
			}
		case "tool_use":
			if ctx, ok := toolContext[extID]; ok {
				resp.Tool = ctx
			}
		case "mcp_call":
			if ctx, ok := mcpContext[extID]; ok {
				resp.MCP = ctx
			}
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

func parseOptionalBounds(c *gin.Context) (pgtype.Timestamptz, pgtype.Timestamptz, bool) {
	var since pgtype.Timestamptz
	var until pgtype.Timestamptz

	sinceStr := strings.TrimSpace(c.Query("since"))
	if sinceStr != "" {
		timestamp, err := parseSinceParam(sinceStr)
		if err != nil {
			respondError(c, http.StatusBadRequest, "validation_failed", err.Error(), nil)
			return pgtype.Timestamptz{}, pgtype.Timestamptz{}, false
		}
		since = pgtype.Timestamptz{Time: timestamp, Valid: true}
	}

	untilStr := strings.TrimSpace(c.Query("until"))
	if untilStr != "" {
		timestamp, err := parseSinceParam(untilStr)
		if err != nil {
			respondError(c, http.StatusBadRequest, "validation_failed", err.Error(), nil)
			return pgtype.Timestamptz{}, pgtype.Timestamptz{}, false
		}
		if since.Valid && timestamp.Before(since.Time) {
			respondError(c, http.StatusBadRequest, "validation_failed", "until must be greater than or equal to since", nil)
			return pgtype.Timestamptz{}, pgtype.Timestamptz{}, false
		}
		until = pgtype.Timestamptz{Time: timestamp, Valid: true}
	}

	return since, until, true
}

func parseRangeParams(c *gin.Context) (string, time.Time, time.Time, int32, bool) {
	host := c.Query("host")
	if host == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "host is required", nil)
		return "", time.Time{}, time.Time{}, 0, false
	}

	sinceStr := c.Query("since")
	if sinceStr == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "since is required", nil)
		return "", time.Time{}, time.Time{}, 0, false
	}

	since, err := parseSinceParam(sinceStr)
	if err != nil {
		respondError(c, http.StatusBadRequest, "validation_failed", err.Error(), nil)
		return "", time.Time{}, time.Time{}, 0, false
	}

	untilStr := strings.TrimSpace(c.Query("until"))
	var until time.Time
	if untilStr == "" {
		until = time.Now().UTC()
	} else {
		until, err = parseSinceParam(untilStr)
		if err != nil {
			respondError(c, http.StatusBadRequest, "validation_failed", err.Error(), nil)
			return "", time.Time{}, time.Time{}, 0, false
		}
	}

	if until.Before(since) {
		respondError(c, http.StatusBadRequest, "validation_failed", "until must be greater than or equal to since", nil)
		return "", time.Time{}, time.Time{}, 0, false
	}

	limitStr := c.DefaultQuery("limit", "100")
	limit64, err := strconv.ParseInt(limitStr, 10, 32)
	if err != nil || limit64 <= 0 {
		respondError(c, http.StatusBadRequest, "validation_failed", "limit must be positive integer", nil)
		return "", time.Time{}, time.Time{}, 0, false
	}

	return host, since, until, int32(limit64), true
}

func parseSinceParam(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, fmt.Errorf("since is required")
	}

	candidates := []string{trimmed}
	if strings.Contains(trimmed, " ") {
		if alt := strings.Replace(trimmed, " ", "+", 1); alt != trimmed {
			candidates = append([]string{alt}, candidates...)
		}
	}

	for _, candidate := range candidates {
		if ts, err := time.Parse(time.RFC3339Nano, candidate); err == nil {
			return ts, nil
		}
		if ts, err := time.Parse(time.RFC3339, candidate); err == nil {
			return ts, nil
		}
	}

	const (
		iso8601NoTZ      = "2006-01-02T15:04:05"
		iso8601NoTZSpace = "2006-01-02 15:04:05"
	)

	for _, candidate := range candidates {
		if ts, err := time.Parse(iso8601NoTZ, candidate); err == nil {
			return ts.UTC(), nil
		}
		if ts, err := time.Parse(iso8601NoTZSpace, candidate); err == nil {
			return ts.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("since must be RFC3339")
}

func parseLimitQuery(c *gin.Context, key string, defaultVal, minVal, maxVal int32) (int32, bool) {
	defStr := fmt.Sprintf("%d", defaultVal)
	valueStr := c.DefaultQuery(key, defStr)
	value64, err := strconv.ParseInt(valueStr, 10, 32)
	if err != nil {
		respondError(c, http.StatusBadRequest, "validation_failed", fmt.Sprintf("%s must be an integer", key), nil)
		return 0, false
	}
	if value64 < int64(minVal) {
		respondError(c, http.StatusBadRequest, "validation_failed", fmt.Sprintf("%s must be >= %d", key, minVal), nil)
		return 0, false
	}
	if maxVal > 0 && value64 > int64(maxVal) {
		respondError(c, http.StatusBadRequest, "validation_failed", fmt.Sprintf("%s must be <= %d", key, maxVal), nil)
		return 0, false
	}
	return int32(value64), true
}

func boolPtrValue(v bool) *bool {
	val := v
	return &val
}

func stringPtrIfNotEmpty(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	val := v
	return &val
}

func zeroIfNil(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

const nullRootKey = "__root_null__"

func rootKeyFromValues(rootPID *int64, rootExecID *string) string {
	if rootPID != nil {
		return fmt.Sprintf("pid:%d", *rootPID)
	}
	if rootExecID != nil {
		trimmed := strings.TrimSpace(*rootExecID)
		if trimmed != "" {
			return "exec:" + trimmed
		}
	}
	return nullRootKey
}

func buildProcessTree(node *treeNode) ProcessTreeNodeResponse {
	resp := node.data
	resp.Children = nil
	if len(node.children) > 0 {
		resp.Children = make([]ProcessTreeNodeResponse, len(node.children))
		for i, child := range node.children {
			resp.Children[i] = buildProcessTree(child)
		}
	}
	return resp
}

func convertHeuristicAlertWithDetails(row sqlc.HeuristicAlert, details []byte) HeuristicAlertResponse {
	return HeuristicAlertResponse{
		AlertID:    row.AlertID,
		AlertType:  row.AlertType,
		Host:       row.Host,
		Severity:   stringPtrFromText(row.Severity),
		Score:      float64PtrFromFloat8(row.Score),
		StartTs:    timePtrFromTimestamptz(row.StartTs),
		EndTs:      timePtrFromTimestamptz(row.EndTs),
		RootExecID: stringPtrFromText(row.RootExecID),
		RootPID:    int64PtrFromInt8(row.RootPid),
		Details:    jsonInterface(details),
		Reason:     stringPtrFromText(row.Reason),
	}
}

func (h analyticsHandlers) enrichPromptInjectionAlertDetails(ctx context.Context, row sqlc.HeuristicAlert) []byte {
	if row.AlertType != "prompt_injection" {
		return row.Details
	}

	// If details already include evidence, return as-is.
	if hasJSONKey(row.Details, "evidence") {
		return row.Details
	}

	requestIDStr := extractRequestIDFromAlertDetails(row.Details)
	if requestIDStr == "" {
		requestIDStr = extractRequestIDFromAlertID(row.AlertID)
	}
	if requestIDStr == "" {
		return row.Details
	}

	reqUUID, err := uuid.Parse(requestIDStr)
	if err != nil {
		return row.Details
	}

	meta, err := h.queries.GetPromptInjectionMetadataByHostAndRequestID(ctx, sqlc.GetPromptInjectionMetadataByHostAndRequestIDParams{
		Host:      row.Host,
		RequestID: pgtype.UUID{Bytes: reqUUID, Valid: true},
	})
	if err != nil || len(meta) == 0 {
		return row.Details
	}

	evidence := extractPromptEvidence(meta)
	if len(evidence) == 0 {
		return row.Details
	}

	detailsObj := map[string]any{}
	if len(row.Details) > 0 {
		_ = json.Unmarshal(row.Details, &detailsObj)
	}
	detailsObj["evidence"] = json.RawMessage(evidence)

	merged, err := json.Marshal(detailsObj)
	if err != nil {
		return row.Details
	}
	return merged
}

func extractRequestIDFromAlertID(alertID string) string {
	parts := strings.Split(alertID, ":")
	if len(parts) < 4 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func extractRequestIDFromAlertDetails(details []byte) string {
	if len(details) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(details, &obj); err != nil {
		return ""
	}
	if v, ok := obj["request_id"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func hasJSONKey(raw []byte, key string) bool {
	if len(raw) == 0 || key == "" {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false
	}
	_, ok := obj[key]
	return ok
}

func convertAgentRun(row sqlc.AgentRun) AgentRunResponse {
	return AgentRunResponse{
		ID:         uuidStringFromUUID(row.ID),
		Host:       row.Host,
		RootExecID: stringPtrFromText(row.RootExecID),
		RootPID:    int64PtrFromInt8(row.RootPid),
		Provider:   stringPtrFromText(row.Provider),
		StartedAt:  timePtrFromTimestamptz(row.StartedAt),
		EndedAt:    timePtrFromTimestamptz(row.EndedAt),
	}
}

func parseCategories(v pgtype.Text) []string {
	if !v.Valid {
		return nil
	}
	raw := strings.TrimSpace(v.String)
	if raw == "" {
		return nil
	}

	var result []string
	var jsonArray []string
	if err := json.Unmarshal([]byte(raw), &jsonArray); err == nil {
		result = jsonArray
	} else {
		parts := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n'
		})
		for _, part := range parts {
			value := strings.TrimSpace(part)
			if value != "" {
				result = append(result, value)
			}
		}
	}

	result = uniqueStrings(result)
	if len(result) == 0 {
		return nil
	}
	return result
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	ordered := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		ordered = append(ordered, trimmed)
	}
	return ordered
}

func jsonInterface(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	return jsonRaw(b)
}

func jsonFromAny(value interface{}) json.RawMessage {
	switch v := value.(type) {
	case nil:
		return nil
	case json.RawMessage:
		return jsonRaw(v)
	case []byte:
		return jsonInterface(v)
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		return jsonRaw([]byte(trimmed))
	default:
		b, err := json.Marshal(v)
		if err != nil || len(b) == 0 {
			return nil
		}
		return jsonRaw(b)
	}
}

func previewFromJSON(raw json.RawMessage, limit int) *string {
	if len(raw) == 0 || limit <= 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	trimmed = textencoding.RepairUTF8Mojibake(trimmed)
	if trimmed == "" {
		return nil
	}
	runes := []rune(trimmed)
	if len(runes) > limit {
		trimmed = string(runes[:limit]) + "..."
	}
	return &trimmed
}

func stringFromAny(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}
