package httpapi

import (
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

	"github.com/tensorchord/watchu/pkg/gen/sqlc"
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
	RequestID  *string    `json:"request_id,omitempty"`
	Severity   *string    `json:"severity,omitempty"`
	Categories []string   `json:"categories,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
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
	ContentLength *int64          `json:"content_length,omitempty"`
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
	group.GET("/heuristic_alerts", h.getHeuristicAlerts)
	group.GET("/process_http_events", h.getHTTPEvents)
	group.GET("/security_llm_analysis", h.getSecurityLLMAnalysis)
	group.GET("/prompt_injections/:request_id", h.getPromptInjectionDetails)
	group.GET("/process_events", h.getProcessEvents)
	group.GET("/process_tree", h.getProcessTree)
	group.GET("/process_summary/:root_pid", h.getProcessSummary)
}

// getCorrelations godoc
// @Summary      List correlation summaries
// @Description  Returns correlation summaries for a host since the provided timestamp.
// @Tags         analytics
// @Produce      json
// @Param        host  query     string true  "Target host"
// @Param        since query     string true  "RFC3339 timestamp lower bound"
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   CorrelationSummaryResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/correlation_summaries [get]
func (h analyticsHandlers) getCorrelations(c *gin.Context) {
	host, since, limit, ok := parseCommonParams(c)
	if !ok {
		return
	}
	rows, err := h.queries.ListCorrelationsByHostSince(c.Request.Context(), sqlc.ListCorrelationsByHostSinceParams{
		Host:       host,
		ResponseTs: pgtype.Timestamptz{Time: since, Valid: true},
		Limit:      limit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
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
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   HeuristicAlertResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/heuristic_alerts [get]
func (h analyticsHandlers) getHeuristicAlerts(c *gin.Context) {
	host, since, limit, ok := parseCommonParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListHeuristicAlertsByHostSince(c.Request.Context(), sqlc.ListHeuristicAlertsByHostSinceParams{
		Host:    host,
		StartTs: pgtype.Timestamptz{Time: since, Valid: true},
		Limit:   limit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	resp := make([]HeuristicAlertResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, convertHeuristicAlert(row))
	}

	c.JSON(http.StatusOK, resp)
}

// getHTTPEvents godoc
// @Summary      List process HTTP events
// @Description  Returns process HTTP events for a host since the provided timestamp.
// @Tags         analytics
// @Produce      json
// @Param        host  query     string true  "Target host"
// @Param        since query     string true  "RFC3339 timestamp lower bound"
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   ProcessHTTPEventResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/process_http_events [get]
func (h analyticsHandlers) getHTTPEvents(c *gin.Context) {
	host, since, limit, ok := parseCommonParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListProcessHTTPEventsByHostSince(c.Request.Context(), sqlc.ListProcessHTTPEventsByHostSinceParams{
		Host:      host,
		Timestamp: pgtype.Timestamptz{Time: since, Valid: true},
		Limit:     limit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
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
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "host is required"})
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
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	promptRows, err := h.queries.ListPromptInjectionsByHost(ctx, sqlc.ListPromptInjectionsByHostParams{
		Host:  textParam(host),
		Limit: promptLimit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
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
		prompts = append(prompts, PromptInjectionRecord{
			RequestID:  uuidPtrFromUUID(row.RequestID),
			Severity:   stringPtrFromText(row.SeverityLevel),
			Categories: parseCategories(row.Categories),
			ObservedAt: timePtrFromTimestamptz(row.ObservedAt),
		})
	}

	c.JSON(http.StatusOK, SecurityLLMAnalysisResponse{
		Semantic:         semantic,
		PromptInjections: prompts,
	})
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
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "host is required"})
		return
	}

	reqIDStr := strings.TrimSpace(c.Param("request_id"))
	if reqIDStr == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "request_id is required"})
		return
	}

	reqUUID, err := uuid.Parse(reqIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "request_id must be a UUID"})
		return
	}

	idParam := pgtype.UUID{Bytes: reqUUID, Valid: true}

	row, err := h.queries.GetHTTPRequestByHostAndID(c.Request.Context(), sqlc.GetHTTPRequestByHostAndIDParams{
		Host: host,
		ID:   idParam,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "request not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
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
		ContentLength: int64PtrFromInt8(row.ContentLength),
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
// @Param        limit query     int    false "Maximum number of records" minimum(1) maximum(1000)
// @Success      200   {array}   ProcessEventResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /api/v1/analysis/process_events [get]
func (h analyticsHandlers) getProcessEvents(c *gin.Context) {
	host, since, limit, ok := parseCommonParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListProcessEventsByHostSince(c.Request.Context(), sqlc.ListProcessEventsByHostSinceParams{
		Host:    host,
		StartTs: pgtype.Timestamptz{Time: since, Valid: true},
		Limit:   limit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
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
// @Param        root_limit  query     int    false "Maximum unique roots" minimum(1) maximum(100)
// @Param        node_limit  query     int    false "Maximum nodes returned" minimum(1) maximum(2000)
// @Success      200         {array}   ProcessTreeNodeResponse
// @Failure      400         {object}  ErrorResponse
// @Failure      500         {object}  ErrorResponse
// @Router       /api/v1/analysis/process_tree [get]
func (h analyticsHandlers) getProcessTree(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "host is required"})
		return
	}

	rootLimit, ok := parseLimitQuery(c, "root_limit", 5, 1, 100)
	if !ok {
		return
	}

	nodeLimit, ok := parseLimitQuery(c, "node_limit", 500, 1, 2000)
	if !ok {
		return
	}

	rootExecFilter := strings.TrimSpace(c.Query("root_exec_id"))

	var (
		rootIDs         []int64
		includeNullRoot bool
		rootOrder       []string
	)

	if rootPIDStr := strings.TrimSpace(c.Query("root_pid")); rootPIDStr != "" {
		pid, err := strconv.ParseInt(rootPIDStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "root_pid must be an integer"})
			return
		}
		rootIDs = append(rootIDs, pid)
		rootOrder = append(rootOrder, rootKeyFromValues(&pid, nil))
	} else {
		roots, err := h.queries.ListProcessTreeRootsByHost(c.Request.Context(), sqlc.ListProcessTreeRootsByHostParams{
			Host:  host,
			Limit: rootLimit,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
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

	if len(rootIDs) == 0 && !includeNullRoot {
		c.JSON(http.StatusOK, []ProcessTreeNodeResponse{})
		return
	}

	if rootIDs == nil {
		rootIDs = []int64{}
	}

	nodesRows, err := h.queries.ListProcessTreeNodesByRoots(c.Request.Context(), sqlc.ListProcessTreeNodesByRootsParams{
		Host:    host,
		Column2: rootIDs,
		Column3: includeNullRoot,
		Limit:   nodeLimit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
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
		if rootExecFilter != "" {
			if rootExec == nil || *rootExec != rootExecFilter {
				continue
			}
		}

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
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "host is required"})
		return
	}

	rootPIDStr := strings.TrimSpace(c.Param("root_pid"))
	rootPID, err := strconv.ParseInt(rootPIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "root_pid must be an integer"})
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
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "process root not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	if meta.EventCount == 0 {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "process root not found"})
		return
	}

	alerts, err := h.queries.ListHeuristicAlertsByRoot(ctx, sqlc.ListHeuristicAlertsByRootParams{
		Host:    host,
		RootPid: pgtype.Int8{Int64: rootPID, Valid: true},
		Column3: rootExec,
		Limit:   alertsLimit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	alertResponses := make([]HeuristicAlertResponse, 0, len(alerts))
	for _, alert := range alerts {
		alertResponses = append(alertResponses, convertHeuristicAlert(alert))
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

func parseCommonParams(c *gin.Context) (string, time.Time, int32, bool) {
	host := c.Query("host")
	if host == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "host is required"})
		return "", time.Time{}, 0, false
	}

	sinceStr := c.Query("since")
	if sinceStr == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "since is required"})
		return "", time.Time{}, 0, false
	}

	since, err := time.Parse(time.RFC3339Nano, sinceStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "since must be RFC3339"})
		return "", time.Time{}, 0, false
	}

	limitStr := c.DefaultQuery("limit", "100")
	limit64, err := strconv.ParseInt(limitStr, 10, 32)
	if err != nil || limit64 <= 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "limit must be positive integer"})
		return "", time.Time{}, 0, false
	}

	return host, since, int32(limit64), true
}

func parseLimitQuery(c *gin.Context, key string, defaultVal, minVal, maxVal int32) (int32, bool) {
	defStr := fmt.Sprintf("%d", defaultVal)
	valueStr := c.DefaultQuery(key, defStr)
	value64, err := strconv.ParseInt(valueStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: fmt.Sprintf("%s must be an integer", key)})
		return 0, false
	}
	if value64 < int64(minVal) {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: fmt.Sprintf("%s must be >= %d", key, minVal)})
		return 0, false
	}
	if maxVal > 0 && value64 > int64(maxVal) {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: fmt.Sprintf("%s must be <= %d", key, maxVal)})
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

func convertHeuristicAlert(row sqlc.HeuristicAlert) HeuristicAlertResponse {
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
		Details:    jsonInterface(row.Details),
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
