package httpapi

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tensorchord/watchu/gateway/pkg/securityinsight"
)

// securityInsightHandlers contains handlers for security insight endpoints
type securityInsightHandlers struct {
	service *securityinsight.Service
}

// ThreatAnalysisRequest represents the request body for threat analysis
type ThreatAnalysisRequest struct {
	RootExecID string `json:"root_exec_id" binding:"required"`
}

// ThreatAnalysisResponse represents the response from threat analysis
type ThreatAnalysisResponse struct {
	RootExecID      string                   `json:"root_exec_id"`
	ThreatLevel     int                      `json:"threat_level"`
	ThreatType      string                   `json:"threat_type"`
	Confidence      float64                  `json:"confidence"`
	Summary         string                   `json:"summary"`
	Details         string                   `json:"details"`
	Recommendations []string                 `json:"recommendations"`
	Evidence        []map[string]interface{} `json:"evidence"`
}

// analyzeThreat godoc
// @Summary      Perform deep threat analysis on a process tree
// @Description  Analyzes telemetry data for a specific root_exec_id and returns comprehensive threat assessment
// @Tags         security-insight
// @Accept       json
// @Produce      json
// @Param        body body      ThreatAnalysisRequest true "Analysis request"
// @Success      200  {object}  ThreatAnalysisResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/security-insight/analyze-threat [post]
func (h securityInsightHandlers) analyzeThreat(c *gin.Context) {
	var req ThreatAnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}

	result, err := h.service.AnalyzeThreatByRootExecID(c.Request.Context(), req.RootExecID)
	if err != nil {
		if errors.Is(err, securityinsight.ErrThreatInsightNotInitialized) {
			respondError(c, http.StatusServiceUnavailable, "threat_insight_unavailable", err.Error(), nil)
			return
		}
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	c.JSON(http.StatusOK, ThreatAnalysisResponse{
		RootExecID:      req.RootExecID,
		ThreatLevel:     result.ThreatLevel,
		ThreatType:      result.ThreatType,
		Confidence:      result.Confidence,
		Summary:         result.Summary,
		Details:         result.Details,
		Recommendations: result.Recommendations,
		Evidence:        result.Evidence,
	})
}

// getThreatAnalysis godoc
// @Summary      Retrieve historical threat analysis result
// @Description  Gets the latest threat analysis result for a specific root_exec_id from the database
// @Tags         security-insight
// @Accept       json
// @Produce      json
// @Param        root_exec_id path string true "Root Execution ID"
// @Success      200  {object}  ThreatAnalysisResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/security-insight/analyze-threat/:root_exec_id [get]
func (h securityInsightHandlers) getThreatAnalysis(c *gin.Context) {
	rootExecID := c.Param("root_exec_id")
	if rootExecID == "" {
		respondError(c, http.StatusBadRequest, "bad_request", "root_exec_id parameter is required", nil)
		return
	}

	result, err := h.service.GetThreatAnalysisByRootExecID(c.Request.Context(), rootExecID)
	if err != nil {
		respondError(c, http.StatusNotFound, "not_found", "no analysis result found for this root_exec_id", nil)
		return
	}

	c.JSON(http.StatusOK, ThreatAnalysisResponse{
		RootExecID:      rootExecID,
		ThreatLevel:     result.ThreatLevel,
		ThreatType:      result.ThreatType,
		Confidence:      result.Confidence,
		Summary:         result.Summary,
		Details:         result.Details,
		Recommendations: result.Recommendations,
		Evidence:        result.Evidence,
	})
}

// registerSecurityInsightRoutes registers security insight endpoints
func registerSecurityInsightRoutes(group *gin.RouterGroup, service *securityinsight.Service) {
	if service == nil {
		return
	}
	h := securityInsightHandlers{service: service}

	// Create security-insight sub-group
	securityGroup := group.Group("/security-insight")
	securityGroup.POST("/analyze-threat", h.analyzeThreat)
	securityGroup.GET("/analyze-threat/:root_exec_id", h.getThreatAnalysis)
}
