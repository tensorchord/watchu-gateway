package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tensorchord/watchu/gateway/pkg/ingest"
)

type ingestHandlers struct {
	svc *ingest.Service
}

func registerIngestRoutes(group *gin.RouterGroup, svc *ingest.Service) {
	h := ingestHandlers{svc: svc}
	group.POST("/http_request", h.postHTTPRequests)
	group.POST("/http_response", h.postHTTPResponses)
	group.POST("/exec_event", h.postExecEvents)
	group.POST("/mcp_stdio", h.postMCPSTDIOEvents)
	group.POST("/pg_event", h.postPGEvents)
}

// postHTTPRequests godoc
// @Summary Ingest HTTP request events
// @Description Accepts a batch of HTTP request telemetry events for bulk ingestion.
// @Tags ingest
// @Accept json
// @Produce json
// @Param payload body HTTPRequestBatch true "HTTP request batch"
// @Success 202
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/ingest/http_request [post]
func (h ingestHandlers) postHTTPRequests(c *gin.Context) {
	var payload HTTPRequestBatch
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if len(payload.Events) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "events must not be empty"})
		return
	}
	if err := h.svc.IngestHTTPRequests(c.Request.Context(), payload.Events); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}

// postHTTPResponses godoc
// @Summary Ingest HTTP response events
// @Description Accepts a batch of HTTP response telemetry events for bulk ingestion.
// @Tags ingest
// @Accept json
// @Produce json
// @Param payload body HTTPResponseBatch true "HTTP response batch"
// @Success 202
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/ingest/http_response [post]
func (h ingestHandlers) postHTTPResponses(c *gin.Context) {
	var payload HTTPResponseBatch
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if len(payload.Events) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "events must not be empty"})
		return
	}
	if err := h.svc.IngestHTTPResponses(c.Request.Context(), payload.Events); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}

// postExecEvents godoc
// @Summary Ingest exec events
// @Description Accepts a batch of process execution telemetry events for bulk ingestion.
// @Tags ingest
// @Accept json
// @Produce json
// @Param payload body ExecEventBatch true "Exec event batch"
// @Success 202
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/ingest/exec_event [post]
func (h ingestHandlers) postExecEvents(c *gin.Context) {
	var payload ExecEventBatch
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if len(payload.Events) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "events must not be empty"})
		return
	}
	if err := h.svc.IngestExecEvents(c.Request.Context(), payload.Events); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}

// postMCPSTDIOEvents godoc
// @Summary Ingest STDIO MCP events
// @Description Accepts MCP JSON-RPC events captured from STDIO transports.
// @Tags ingest
// @Accept json
// @Produce json
// @Param payload body MCPSTDIOBatch true "STDIO MCP batch"
// @Success 202
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/ingest/mcp_stdio [post]
func (h ingestHandlers) postMCPSTDIOEvents(c *gin.Context) {
	var payload MCPSTDIOBatch
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if len(payload.Events) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "events must not be empty"})
		return
	}
	if err := h.svc.IngestMCPSTDIOEvents(c.Request.Context(), payload.Events); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}

// postPGEvents godoc
// @Summary Ingest Postgres client protocol events
// @Description Accepts a batch of Postgres frontend message (client → server) events for bulk ingestion.
// @Tags ingest
// @Accept json
// @Produce json
// @Param payload body PGEventBatch true "Postgres event batch"
// @Success 202
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/ingest/pg_event [post]
func (h ingestHandlers) postPGEvents(c *gin.Context) {
	var payload PGEventBatch
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if len(payload.Events) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "events must not be empty"})
		return
	}
	if err := h.svc.IngestPGEvents(c.Request.Context(), payload.Events); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Status(http.StatusAccepted)
}
