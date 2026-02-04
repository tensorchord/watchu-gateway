package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/s3"
	"github.com/tensorchord/watchu/gateway/pkg/securityinsight"
	"github.com/tensorchord/watchu/gateway/pkg/skillsecurity"
)

type skillSecuritySaaSHandlers struct {
	queries         *sqlc.Queries
	skillSec        *skillsecurity.Service
	runner          skillsecurity.Runner
	s3              *s3.Client
	securityInsight *securityinsight.Service
}

func registerSkillSecuritySaaSInternalRoutes(router *gin.RouterGroup, queries *sqlc.Queries, skillSec *skillsecurity.Service, securityInsight *securityinsight.Service) {
	if queries == nil {
		return
	}

	h := &skillSecuritySaaSHandlers{
		queries:         queries,
		skillSec:        skillSec,
		securityInsight: securityInsight,
	}

	// Extract runner and s3 from skillSec if available
	if skillSec != nil {
		// Access runner through the service
		// Note: This requires skillsecurity.Service to expose these or we create them here
	}

	internalAPI := router.Group("/internal/saas")
	{
		// Skills
		skills := internalAPI.Group("/skills")
		{
			skills.POST("", h.createSkill)
			skills.GET("", h.listSkills)
			skills.GET("/:id", h.getSkill)
			skills.PUT("/:id", h.updateSkill)
			skills.DELETE("/:id", h.deleteSkill)
			skills.GET("/:id/notifications", h.getSkillNotifications)
		}

		// Analyses
		analyses := internalAPI.Group("/analyses")
		{
			analyses.POST("", h.createAnalysis)
			analyses.GET("", h.listAnalyses)
			analyses.GET("/:id", h.getAnalysis)
			analyses.GET("/:id/security-events", h.getSecurityEvents)
			analyses.GET("/:id/threat", h.getAnalysisThreat)
			analyses.GET("/:id/notifications", h.getAnalysisNotifications)
			analyses.POST("/:id/rerun", h.rerunAnalysis)
			analyses.DELETE("/:id", h.deleteAnalysis)
		}

		// Notifications
		notifications := internalAPI.Group("/notifications")
		{
			notifications.GET("", h.listNotificationsByQuery)
			notifications.GET("/:id", h.getNotification)
			notifications.POST("/:id/read", h.markNotificationAsRead)
			notifications.POST("/:id/dismiss", h.dismissNotification)
		}

		// User notifications
		users := internalAPI.Group("/users/:userId")
		{
			users.GET("/notifications", h.listNotifications)
			users.POST("/notifications/read-all", h.markAllAsRead)
			users.GET("/notifications/unread-count", h.getUnreadCount)
		}
	}
}

// Request/Response types
type CreateSkillRequest struct {
	Name          string                 `json:"name" binding:"required"`
	Description   *string                `json:"description,omitempty"`
	SourceType    string                 `json:"source_type" binding:"required"`
	SourceURI     *string                `json:"source_uri,omitempty"`
	S3Path        string                 `json:"s3_path" binding:"required"`
	S3Bucket      string                 `json:"s3_bucket" binding:"required"`
	Checksum      string                 `json:"checksum" binding:"required"`
	SizeBytes     *int64                 `json:"size_bytes,omitempty"`
	ContentType   *string                `json:"content_type,omitempty"`
	Version       string                 `json:"version"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type CreateAnalysisRequest struct {
	SkillID        string  `json:"skill_id" binding:"required"`
	PromptStrategy *string `json:"prompt_strategy,omitempty"`
	PromptInput    *string `json:"prompt_input,omitempty"`
}

type SkillResponse struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    *string                `json:"description,omitempty"`
	SourceType     string                 `json:"source_type"`
	SourceURI      *string                `json:"source_uri,omitempty"`
	S3Path         string                 `json:"s3_path"`
	S3Bucket       string                 `json:"s3_bucket"`
	Checksum       *string                `json:"checksum,omitempty"`
	SizeBytes      *int64                 `json:"size_bytes,omitempty"`
	ContentType    *string                `json:"content_type,omitempty"`
	Version        string                 `json:"version"`
	CreatedAt      string                 `json:"created_at"`
	UpdatedAt      string                 `json:"updated_at"`
	LastAnalysisID *string                `json:"last_analysis_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type AnalysisResponse struct {
	ID              string                 `json:"id"`
	SkillID         string                 `json:"skill_id"`
	SkillName       *string                `json:"skill_name,omitempty"`
	SkillSourceType *string                `json:"skill_source_type,omitempty"`
	Status          string                 `json:"status"`
	StartedAt       string                 `json:"started_at"`
	CompletedAt     *string                `json:"completed_at,omitempty"`
	RootExecID      *string                `json:"root_exec_id,omitempty"`
	ErrorMessage    *string                `json:"error_message,omitempty"`
	RunnerOutput    *string                `json:"runner_output,omitempty"`
	RunnerExitCode  *int32                 `json:"runner_exit_code,omitempty"`
	PromptStrategy  string                 `json:"prompt_strategy,omitempty"`
	PromptInput     *string                `json:"prompt_input,omitempty"`
	EngineVersion   *string                `json:"engine_version,omitempty"`
	TotalFindings   *int32                 `json:"total_findings,omitempty"`
	SeveritySummary map[string]interface{} `json:"severity_summary,omitempty"`
	CreatedAt       string                 `json:"created_at"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

type FindingResponse struct {
	ID             string                 `json:"id"`
	AnalysisID     string                 `json:"analysis_id"`
	Severity       string                 `json:"severity"`
	Category       string                 `json:"category"`
	Title          string                 `json:"title"`
	Description    *string                `json:"description,omitempty"`
	Location       *string                `json:"location,omitempty"`
	CodeSnippet    *string                `json:"code_snippet,omitempty"`
	Recommendation *string                `json:"recommendation,omitempty"`
	References     []interface{}          `json:"references,omitempty"`
	CreatedAt      string                 `json:"created_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityEventResponse is the unified response for security events (consolidates findings and security_analyses)
type SecurityEventResponse struct {
	ID                string                 `json:"id"`
	AnalysisID        string                 `json:"analysis_id"`
	SourceType        string                 `json:"source_type"` // static, dynamic, agent, overall
	Severity          string                 `json:"severity"`
	Category          *string                `json:"category,omitempty"`
	Title             string                 `json:"title"`
	Description       *string                `json:"description,omitempty"`
	Confidence        *float64               `json:"confidence,omitempty"`
	CodeSnippet       *string                `json:"code_snippet,omitempty"`       // for static analysis
	FilePath          *string                `json:"file_path,omitempty"`         // for static analysis
	References        []interface{}          `json:"references,omitempty"`
	TelemetrySummary  map[string]interface{} `json:"telemetry_summary,omitempty"`  // for dynamic analysis
	AIGeneratedSummary *string               `json:"ai_generated_summary,omitempty"` // for overall assessment
	Recommendations   []string               `json:"recommendations,omitempty"`
	Evidence          []interface{}          `json:"evidence,omitempty"`
	CreatedAt         string                 `json:"created_at"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

type NotificationResponse struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	AnalysisID  *string                `json:"analysis_id,omitempty"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	ReadAt      *string                `json:"read_at,omitempty"`
	DismissedAt *string                `json:"dismissed_at,omitempty"`
	CreatedAt   string                 `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Skills handlers
func (h *skillSecuritySaaSHandlers) createSkill(c *gin.Context) {
	var req CreateSkillRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	metadataJSON, _ := json.Marshal(req.Metadata)

	// Normalize s3_path to have leading / for proper S3 path construction
	s3Path := req.S3Path
	if !strings.HasPrefix(s3Path, "/") {
		s3Path = "/" + s3Path
	}

	skill, err := h.queries.CreateSaaSSkill(c.Request.Context(), sqlc.CreateSaaSSkillParams{
		Name:       req.Name,
		Description: textPtrFromPtr(req.Description),
		SourceType:  req.SourceType,
		SourceUri:   textPtrFromPtr(req.SourceURI),
		S3Path:      s3Path,
		S3Bucket:    req.S3Bucket,
		Checksum:    textPtr(req.Checksum),
		SizeBytes:   int8PtrFromPtr(req.SizeBytes),
		ContentType: textPtrFromPtr(req.ContentType),
		Version:     textPtr(req.Version),
		Metadata:    metadataJSON,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, toSkillResponse(skill))
}

func (h *skillSecuritySaaSHandlers) getSkill(c *gin.Context) {
	id := c.Param("id")
	skillUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid skill ID"})
		return
	}

	skill, err := h.queries.GetSaaSSkillByID(c.Request.Context(), pgtype.UUID{Bytes: skillUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "skill not found"})
		return
	}

	c.JSON(http.StatusOK, toSkillResponse(skill))
}

func (h *skillSecuritySaaSHandlers) listSkills(c *gin.Context) {
	limit := int32(100)
	offset := int32(0)

	skills, err := h.queries.ListSaaSSkills(c.Request.Context(), sqlc.ListSaaSSkillsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]SkillResponse, len(skills))
	for i, s := range skills {
		response[i] = toSkillResponse(s)
	}

	c.JSON(http.StatusOK, response)
}

func (h *skillSecuritySaaSHandlers) updateSkill(c *gin.Context) {
	id := c.Param("id")
	skillUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid skill ID"})
		return
	}

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Handle soft delete via deleted_at
	var deletedAt pgtype.Timestamptz
	if deletedAtStr, ok := req["deleted_at"].(string); ok && deletedAtStr != "" {
		if t, err := time.Parse(time.RFC3339, deletedAtStr); err == nil {
			deletedAt = pgtype.Timestamptz{Time: t, Valid: true}
		}
	}

	skill, err := h.queries.UpdateSaaSSkill(c.Request.Context(), sqlc.UpdateSaaSSkillParams{
		Name:        "", // Empty string for COALESCE to not update
		Description: pgtype.Text{},
		Metadata:    nil,
		DeletedAt:   deletedAt,
		ID:          pgtype.UUID{Bytes: skillUUID, Valid: true},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// If this is a soft delete operation, cascade delete related analyses and notifications
	if deletedAt.Valid {
		// Cascade soft delete analyses
		if err := h.queries.CascadeSoftDeleteAnalysesBySkillID(c.Request.Context(),
			sqlc.CascadeSoftDeleteAnalysesBySkillIDParams{
				SkillID:   pgtype.UUID{Bytes: skillUUID, Valid: true},
				DeletedAt: deletedAt,
			}); err != nil {
			// Log error but don't fail - skill was already deleted
			fmt.Fprintf(os.Stderr, "WARNING: Failed to cascade delete analyses: %v\n", err)
		}

		// Cascade soft delete notifications by skill_id
		if err := h.queries.CascadeSoftDeleteNotificationsBySkillID(c.Request.Context(),
			sqlc.CascadeSoftDeleteNotificationsBySkillIDParams{
				SkillID:   pgtype.UUID{Bytes: skillUUID, Valid: true},
				DeletedAt: deletedAt,
			}); err != nil {
			// Log error but don't fail - skill was already deleted
			fmt.Fprintf(os.Stderr, "WARNING: Failed to cascade delete notifications by skill_id: %v\n", err)
		}
	}

	c.JSON(http.StatusOK, toSkillResponse(skill))
}

func (h *skillSecuritySaaSHandlers) deleteSkill(c *gin.Context) {
	id := c.Param("id")
	skillUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid skill ID"})
		return
	}

	err = h.queries.DeleteSaaSSkill(c.Request.Context(), pgtype.UUID{Bytes: skillUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// Analyses handlers
func (h *skillSecuritySaaSHandlers) createAnalysis(c *gin.Context) {
	var req CreateAnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Check for empty or missing skill_id
	if req.SkillID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "skill_id is required"})
		return
	}

	skillID, err := uuid.Parse(req.SkillID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid skill ID format"})
		return
	}

	// Check for zero UUID (indicates analysis has no associated skill)
	if skillID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "analysis has no associated skill, cannot rerun"})
		return
	}

	// Get skill to retrieve S3 path
	skill, err := h.queries.GetSaaSSkillByID(c.Request.Context(), pgtype.UUID{Bytes: skillID, Valid: true})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "skill not found"})
		return
	}

	// Build artifact path from S3 info (ensure / separator between bucket and path)
	artifactPath := "s3://" + skill.S3Bucket + "/" + strings.TrimPrefix(skill.S3Path, "/")

	// Normalize prompt strategy
	promptStrategy := "from-skill"
	promptInput := ""
	if req.PromptStrategy != nil && *req.PromptStrategy != "" {
		promptStrategy = *req.PromptStrategy
	}
	if req.PromptInput != nil && *req.PromptInput != "" {
		promptInput = *req.PromptInput
	}

	// Use skillsecurity.Service to create run (this writes to skill_analyses and calls runner)
	if h.skillSec == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "skill security service not configured"})
		return
	}

	sourceRef := strings.TrimSpace(stringFromText(skill.SourceUri))
	if sourceRef == "" {
		sourceRef = strings.TrimSpace(skill.Name)
	}

	analysis, err := h.skillSec.CreateRun(c.Request.Context(), skillsecurity.CreateRunInput{
		SkillID:        pgtype.UUID{Bytes: skillID, Valid: true},
		SourceType:     skill.SourceType,
		SourceRef:      sourceRef,
		ArtifactPath:   artifactPath,
		AgentType:      "claude-code",
		RunnerMode:     "docker",
		PromptStrategy: promptStrategy,
		PromptInput:    promptInput,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, toAnalysisResponse(analysis))
}

func (h *skillSecuritySaaSHandlers) getAnalysis(c *gin.Context) {
	id := c.Param("id")
	analysisUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	analysis, err := h.queries.GetSaaSSkillAnalysisByID(c.Request.Context(), pgtype.UUID{Bytes: analysisUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "analysis not found"})
		return
	}

	c.JSON(http.StatusOK, toAnalysisResponseWithSkill(analysis))
}

func (h *skillSecuritySaaSHandlers) listAnalyses(c *gin.Context) {
	limit := int32(100)
	offset := int32(0)

	analyses, err := h.queries.ListSaaSSkillAnalyses(c.Request.Context(), sqlc.ListSaaSSkillAnalysesParams{
		Column1: "",
		Column2: "",
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]AnalysisResponse, len(analyses))
	for i, a := range analyses {
		response[i] = toAnalysisResponseWithSkill(a)
	}

	c.JSON(http.StatusOK, response)
}

func (h *skillSecuritySaaSHandlers) getSecurityEvents(c *gin.Context) {
	id := c.Param("id")
	analysisUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	// Query security_events from the unified table
	events, err := h.queries.GetSecurityEventsByAnalysisID(c.Request.Context(), pgtype.UUID{Bytes: analysisUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filter out unified events (avoid duplication - unified is for threat API only)
	var filteredEvents []sqlc.SecurityEvent
	for _, event := range events {
		if event.SourceType != "unified" {
			filteredEvents = append(filteredEvents, event)
		}
	}

	// Convert security events to response format
	response := make([]SecurityEventResponse, len(filteredEvents))
	for i, event := range filteredEvents {
		response[i] = toSecurityEventResponse(event)
	}

	c.JSON(http.StatusOK, response)
}

// SaaSThreatAnalysisResponse is the response structure for threat analysis in SaaS API
type SaaSThreatAnalysisResponse struct {
	RootExecID      *string                  `json:"root_exec_id,omitempty"`
	ThreatLevel     *int                     `json:"threat_level,omitempty"`
	ThreatType      *string                  `json:"threat_type,omitempty"`
	Confidence      *float64                 `json:"confidence,omitempty"`
	Summary         string                   `json:"summary"`
	Details         *string                  `json:"details,omitempty"`
	Recommendations []string                 `json:"recommendations,omitempty"`
	Evidence        []map[string]interface{} `json:"evidence,omitempty"`
	AnalysisReady   bool                     `json:"analysis_ready"`
	Status          string                   `json:"status"`
}

func (h *skillSecuritySaaSHandlers) getAnalysisThreat(c *gin.Context) {
	id := c.Param("id")
	analysisUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	// Get analysis to find root_exec_id
	analysis, err := h.queries.GetSkillAnalysisByID(c.Request.Context(), pgtype.UUID{Bytes: analysisUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "analysis not found"})
		return
	}

	// Check if root_exec_id exists
	if !analysis.RootExecID.Valid || analysis.RootExecID.String == "" {
		// Analysis doesn't have root_exec_id yet - return pending message
		c.JSON(http.StatusOK, SaaSThreatAnalysisResponse{
			Summary: "Threat analysis not yet available. The analysis is waiting for process telemetry to be correlated.",
			AnalysisReady: false,
			Status:        "pending",
		})
		return
	}

	// Check if securityInsight service is available
	if h.securityInsight == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "security insight service not configured"})
		return
	}

	// Get threat analysis using analysis_id (now queries by specific skill_analysis instead of root_exec_id)
	result, err := h.securityInsight.GetThreatAnalysis(c.Request.Context(), pgtype.UUID{Bytes: analysisUUID, Valid: true})
	if err != nil {
		// No threat analysis found - return pending message with root_exec_id
		rootExecID := analysis.RootExecID.String
		c.JSON(http.StatusOK, SaaSThreatAnalysisResponse{
			RootExecID: &rootExecID,
			Summary:    "Threat analysis not yet available. The analysis is waiting for process telemetry to be correlated.",
			AnalysisReady: false,
			Status:        "pending",
		})
		return
	}

	rootExecID := analysis.RootExecID.String
	threatLevel := result.ThreatLevel
	threatType := result.ThreatType
	confidence := result.Confidence
	details := result.Details
	status := result.Status
	if status == "" {
		status = "ready"
	}

	// AnalysisReady should only be true when status is "ready"
	// "pending" and "analyzing" both indicate analysis is not complete
	analysisReady := status == "ready"

	c.JSON(http.StatusOK, SaaSThreatAnalysisResponse{
		RootExecID:      &rootExecID,
		ThreatLevel:     &threatLevel,
		ThreatType:      &threatType,
		Confidence:      &confidence,
		Summary:         result.Summary,
		Details:         &details,
		Recommendations: result.Recommendations,
		Evidence:        result.Evidence,
		AnalysisReady:   analysisReady,
		Status:          status,
	})
}

func (h *skillSecuritySaaSHandlers) getAnalysisNotifications(c *gin.Context) {
	id := c.Param("id")
	analysisUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	notifications, err := h.queries.GetSaaSNotificationsByAnalysisID(c.Request.Context(), pgtype.UUID{Bytes: analysisUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]NotificationResponse, len(notifications))
	for i, n := range notifications {
		response[i] = toNotificationResponse(n)
	}

	c.JSON(http.StatusOK, response)
}

func (h *skillSecuritySaaSHandlers) getSkillNotifications(c *gin.Context) {
	id := c.Param("id")
	skillUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid skill ID"})
		return
	}

	limit := int32(100)
	offset := int32(0)

	notifications, err := h.queries.GetSaaSNotificationsBySkillID(c.Request.Context(), sqlc.GetSaaSNotificationsBySkillIDParams{
		SkillID: pgtype.UUID{Bytes: skillUUID, Valid: true},
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]NotificationResponse, len(notifications))
	for i, n := range notifications {
		response[i] = toNotificationResponse(n)
	}

	c.JSON(http.StatusOK, response)
}

func (h *skillSecuritySaaSHandlers) rerunAnalysis(c *gin.Context) {
	id := c.Param("id")
	analysisUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	// Get existing analysis
	analysis, err := h.queries.GetSkillAnalysisByID(c.Request.Context(), pgtype.UUID{Bytes: analysisUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "analysis not found"})
		return
	}

	// Get skill for artifact path
	if !analysis.SkillID.Valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "analysis has no associated skill"})
		return
	}
	skill, err := h.queries.GetSaaSSkillByID(c.Request.Context(), analysis.SkillID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "skill not found"})
		return
	}

	// Build artifact path from S3 info (ensure / separator between bucket and path)
	artifactPath := "s3://" + skill.S3Bucket + "/" + strings.TrimPrefix(skill.S3Path, "/")

	// Rerun using the same analysis ID
	updatedAnalysis, err := h.skillSec.RerunAnalysis(c.Request.Context(), analysis, artifactPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, toAnalysisResponse(updatedAnalysis))
}

func (h *skillSecuritySaaSHandlers) deleteAnalysis(c *gin.Context) {
	id := c.Param("id")
	analysisUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis ID"})
		return
	}

	err = h.queries.DeleteSaaSSkillAnalysis(c.Request.Context(), pgtype.UUID{Bytes: analysisUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// Notifications handlers
func (h *skillSecuritySaaSHandlers) getNotification(c *gin.Context) {
	// For simplicity, return error - implement GetSaaSNotificationByID query if needed
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// listNotificationsByQuery retrieves notifications based on query parameters
// Supports: ?analysis_id=xxx or ?skill_id=xxx or ?user_id=xxx
func (h *skillSecuritySaaSHandlers) listNotificationsByQuery(c *gin.Context) {
	limit := int32(100)
	offset := int32(0)
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.ParseInt(o, 10, 32); err == nil {
			offset = int32(parsed)
		}
	}

	var notifications []sqlc.Notification
	var err error

	// Check which filter is provided
	if analysisID := c.Query("analysis_id"); analysisID != "" {
		parsedUUID, parseErr := uuid.Parse(analysisID)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid analysis_id"})
			return
		}
		notifications, err = h.queries.GetSaaSNotificationsByAnalysisID(c.Request.Context(), pgtype.UUID{Bytes: parsedUUID, Valid: true})
	} else if skillID := c.Query("skill_id"); skillID != "" {
		parsedUUID, parseErr := uuid.Parse(skillID)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid skill_id"})
			return
		}
		notifications, err = h.queries.GetSaaSNotificationsBySkillID(c.Request.Context(), sqlc.GetSaaSNotificationsBySkillIDParams{
			SkillID: pgtype.UUID{Bytes: parsedUUID, Valid: true},
			Limit:   limit,
			Offset:  offset,
		})
	} else if userID := c.Query("user_id"); userID != "" {
		notifications, err = h.queries.GetSaaSNotificationsByUserID(c.Request.Context(), sqlc.GetSaaSNotificationsByUserIDParams{
			UserID: pgtype.Text{String: userID, Valid: true},
			Limit:  limit,
			Offset: offset,
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Must provide one of: analysis_id, skill_id, or user_id query parameter"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]NotificationResponse, len(notifications))
	for i, n := range notifications {
		response[i] = toNotificationResponse(n)
	}

	c.JSON(http.StatusOK, response)
}

func (h *skillSecuritySaaSHandlers) listNotifications(c *gin.Context) {
	userID := c.Param("userId")
	limit := int32(100)
	offset := int32(0)

	notifications, err := h.queries.GetSaaSNotificationsByUserID(c.Request.Context(), sqlc.GetSaaSNotificationsByUserIDParams{
		UserID: pgtype.Text{String: userID, Valid: true},
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]NotificationResponse, len(notifications))
	for i, n := range notifications {
		response[i] = toNotificationResponse(n)
	}

	c.JSON(http.StatusOK, response)
}

func (h *skillSecuritySaaSHandlers) markNotificationAsRead(c *gin.Context) {
	id := c.Param("id")
	notificationUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
		return
	}

	_, err = h.queries.MarkSaaSNotificationAsRead(c.Request.Context(), pgtype.UUID{Bytes: notificationUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *skillSecuritySaaSHandlers) dismissNotification(c *gin.Context) {
	id := c.Param("id")
	notificationUUID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
		return
	}

	_, err = h.queries.DismissSaaSNotification(c.Request.Context(), pgtype.UUID{Bytes: notificationUUID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *skillSecuritySaaSHandlers) markAllAsRead(c *gin.Context) {
	userID := c.Param("userId")

	err := h.queries.MarkAllSaaSNotificationsAsRead(c.Request.Context(), pgtype.Text{String: userID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *skillSecuritySaaSHandlers) getUnreadCount(c *gin.Context) {
	userID := c.Param("userId")

	count, err := h.queries.CountSaaSUnreadNotifications(c.Request.Context(), pgtype.Text{String: userID, Valid: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"unread_count": count})
}

// Helper functions
func toSkillResponse(skill sqlc.Skill) SkillResponse {
	return SkillResponse{
		ID:             uuid.UUID(skill.ID.Bytes).String(),
		Name:           skill.Name,
		Description:    stringPtrFromText(skill.Description),
		SourceType:     skill.SourceType,
		SourceURI:      stringPtrFromText(skill.SourceUri),
		S3Path:         skill.S3Path,
		S3Bucket:       skill.S3Bucket,
		Checksum:       stringPtrFromText(skill.Checksum),
		SizeBytes:      int64PtrFromInt8(skill.SizeBytes),
		ContentType:    stringPtrFromText(skill.ContentType),
		Version:        stringFromText(skill.Version),
		CreatedAt:      skill.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:      skill.UpdatedAt.Time.Format(time.RFC3339),
		LastAnalysisID: uuidPtrFromUUID(skill.LastAnalysisID),
		Metadata:       jsonbToMap(skill.Metadata),
	}
}

func toAnalysisResponse(analysis sqlc.SkillAnalysis) AnalysisResponse {
	var skillID string
	if analysis.SkillID.Valid {
		skillID = uuid.UUID(analysis.SkillID.Bytes).String()
	}
	promptInput := stringPtrFromText(analysis.PromptInput)
	if promptInput != nil && *promptInput != "" {
		cleaned := skillsecurity.StripSecurityAnalysis(*promptInput)
		promptInput = &cleaned
	}
	runnerOutput := stringPtrFromText(analysis.RunnerOutput)
	if runnerOutput != nil && *runnerOutput != "" {
		cleaned := skillsecurity.StripSecurityAnalysis(*runnerOutput)
		runnerOutput = &cleaned
	}
	return AnalysisResponse{
		ID:              uuid.UUID(analysis.ID.Bytes).String(),
		SkillID:         skillID,
		Status:          analysis.Status,
		StartedAt:       analysis.StartedAt.Time.Format(time.RFC3339),
		CompletedAt:     timestamptzPtrToString(analysis.CompletedAt),
		RootExecID:      stringPtrFromText(analysis.RootExecID),
		ErrorMessage:    stringPtrFromText(analysis.ErrorMessage),
		RunnerOutput:    runnerOutput,
		RunnerExitCode:  int32PtrFromInt4(analysis.RunnerExitCode),
		PromptStrategy:  analysis.PromptStrategy,
		PromptInput:     promptInput,
		EngineVersion:   stringPtrFromText(analysis.EngineVersion),
		TotalFindings:   int32PtrFromInt4(analysis.TotalFindings),
		SeveritySummary: jsonbToMap(analysis.SeveritySummary),
		CreatedAt:       analysis.CreatedAt.Time.Format(time.RFC3339),
		Metadata:        jsonbToMap(analysis.Metadata),
	}
}

// toAnalysisResponseWithSkill converts analysis row with skill info to AnalysisResponse
func toAnalysisResponseWithSkill(row interface{}) AnalysisResponse {
	var resp AnalysisResponse

	// Handle different row types with skill info
	switch r := row.(type) {
	case sqlc.GetSaaSSkillAnalysisByIDRow:
		var skillID string
		if r.SkillID.Valid {
			skillID = uuid.UUID(r.SkillID.Bytes).String()
		}
		promptInput := stringPtrFromText(r.PromptInput)
		if promptInput != nil && *promptInput != "" {
			cleaned := skillsecurity.StripSecurityAnalysis(*promptInput)
			promptInput = &cleaned
		}
		runnerOutput := stringPtrFromText(r.RunnerOutput)
		if runnerOutput != nil && *runnerOutput != "" {
			cleaned := skillsecurity.StripSecurityAnalysis(*runnerOutput)
			runnerOutput = &cleaned
		}
		resp = AnalysisResponse{
			ID:              uuid.UUID(r.ID.Bytes).String(),
			SkillID:         skillID,
			Status:          r.Status,
			StartedAt:       r.StartedAt.Time.Format(time.RFC3339),
			CompletedAt:     timestamptzPtrToString(r.CompletedAt),
			RootExecID:      stringPtrFromText(r.RootExecID),
			ErrorMessage:    stringPtrFromText(r.ErrorMessage),
			RunnerOutput:    runnerOutput,
			RunnerExitCode:  int32PtrFromInt4(r.RunnerExitCode),
			PromptStrategy:  r.PromptStrategy,
			PromptInput:     promptInput,
			EngineVersion:   stringPtrFromText(r.EngineVersion),
			TotalFindings:   int32PtrFromInt4(r.TotalFindings),
			SeveritySummary: jsonbToMap(r.SeveritySummary),
			CreatedAt:       r.CreatedAt.Time.Format(time.RFC3339),
			Metadata:        jsonbToMap(r.Metadata),
			SkillName:       stringPtrFromText(r.SkillName),
			SkillSourceType: stringPtrFromText(r.SkillSourceType),
		}
	case sqlc.GetSaaSSkillAnalysesBySkillIDRow:
		var skillID string
		if r.SkillID.Valid {
			skillID = uuid.UUID(r.SkillID.Bytes).String()
		}
		promptInput := stringPtrFromText(r.PromptInput)
		if promptInput != nil && *promptInput != "" {
			cleaned := skillsecurity.StripSecurityAnalysis(*promptInput)
			promptInput = &cleaned
		}
		runnerOutput := stringPtrFromText(r.RunnerOutput)
		if runnerOutput != nil && *runnerOutput != "" {
			cleaned := skillsecurity.StripSecurityAnalysis(*runnerOutput)
			runnerOutput = &cleaned
		}
		resp = AnalysisResponse{
			ID:              uuid.UUID(r.ID.Bytes).String(),
			SkillID:         skillID,
			Status:          r.Status,
			StartedAt:       r.StartedAt.Time.Format(time.RFC3339),
			CompletedAt:     timestamptzPtrToString(r.CompletedAt),
			RootExecID:      stringPtrFromText(r.RootExecID),
			ErrorMessage:    stringPtrFromText(r.ErrorMessage),
			RunnerOutput:    runnerOutput,
			RunnerExitCode:  int32PtrFromInt4(r.RunnerExitCode),
			PromptStrategy:  r.PromptStrategy,
			PromptInput:     promptInput,
			EngineVersion:   stringPtrFromText(r.EngineVersion),
			TotalFindings:   int32PtrFromInt4(r.TotalFindings),
			SeveritySummary: jsonbToMap(r.SeveritySummary),
			CreatedAt:       r.CreatedAt.Time.Format(time.RFC3339),
			Metadata:        jsonbToMap(r.Metadata),
			SkillName:       stringPtrFromText(r.SkillName),
			SkillSourceType: stringPtrFromText(r.SkillSourceType),
		}
	case sqlc.ListSaaSSkillAnalysesRow:
		var skillID string
		if r.SkillID.Valid {
			skillID = uuid.UUID(r.SkillID.Bytes).String()
		}
		promptInput := stringPtrFromText(r.PromptInput)
		if promptInput != nil && *promptInput != "" {
			cleaned := skillsecurity.StripSecurityAnalysis(*promptInput)
			promptInput = &cleaned
		}
		runnerOutput := stringPtrFromText(r.RunnerOutput)
		if runnerOutput != nil && *runnerOutput != "" {
			cleaned := skillsecurity.StripSecurityAnalysis(*runnerOutput)
			runnerOutput = &cleaned
		}
		resp = AnalysisResponse{
			ID:              uuid.UUID(r.ID.Bytes).String(),
			SkillID:         skillID,
			Status:          r.Status,
			StartedAt:       r.StartedAt.Time.Format(time.RFC3339),
			CompletedAt:     timestamptzPtrToString(r.CompletedAt),
			RootExecID:      stringPtrFromText(r.RootExecID),
			ErrorMessage:    stringPtrFromText(r.ErrorMessage),
			RunnerOutput:    runnerOutput,
			RunnerExitCode:  int32PtrFromInt4(r.RunnerExitCode),
			PromptStrategy:  r.PromptStrategy,
			PromptInput:     promptInput,
			EngineVersion:   stringPtrFromText(r.EngineVersion),
			TotalFindings:   int32PtrFromInt4(r.TotalFindings),
			SeveritySummary: jsonbToMap(r.SeveritySummary),
			CreatedAt:       r.CreatedAt.Time.Format(time.RFC3339),
			Metadata:        jsonbToMap(r.Metadata),
			SkillName:       stringPtrFromText(r.SkillName),
			SkillSourceType: stringPtrFromText(r.SkillSourceType),
		}
	}

	return resp
}


// toSecurityEventResponse converts a sqlc.SecurityEvent to SecurityEventResponse
func toSecurityEventResponse(event sqlc.SecurityEvent) SecurityEventResponse {
	resp := SecurityEventResponse{
		ID:         uuid.UUID(event.ID.Bytes).String(),
		AnalysisID: uuid.UUID(event.AnalysisID.Bytes).String(),
		SourceType: event.SourceType,
		Severity:   event.Severity,
		Title:      event.Title,
		CreatedAt:  event.CreatedAt.Time.Format(time.RFC3339),
	}

	if event.Category.Valid {
		resp.Category = &event.Category.String
	}

	resp.Description = stringPtrFromText(event.Description)
	resp.CodeSnippet = stringPtrFromText(event.CodeSnippet)
	resp.FilePath = stringPtrFromText(event.FilePath)

	if event.Confidence.Valid {
		var f float64
		if err := event.Confidence.Scan(&f); err == nil {
			resp.Confidence = &f
		}
	}

	resp.References = jsonBytesToArray(event.ReferenceLinks)
	resp.Evidence = jsonBytesToArray(event.Evidence)
	resp.Metadata = jsonBytesToMap(event.Metadata)

	if len(event.TelemetrySummary) > 0 {
		resp.TelemetrySummary = jsonBytesToMap(event.TelemetrySummary)
	}

	if len(event.Recommendations) > 0 {
		var recs []string
		if err := json.Unmarshal(event.Recommendations, &recs); err == nil {
			resp.Recommendations = recs
		}
	}

	resp.AIGeneratedSummary = stringPtrFromText(event.AiGeneratedSummary)

	return resp
}

// Helper functions for converting jsonb bytes
func jsonBytesToArray(data []byte) []interface{} {
	if len(data) == 0 {
		return nil
	}
	var result []interface{}
	_ = json.Unmarshal(data, &result)
	return result
}

func jsonBytesToMap(data []byte) map[string]interface{} {
	if len(data) == 0 {
		return nil
	}
	var result map[string]interface{}
	_ = json.Unmarshal(data, &result)
	return result
}

func toNotificationResponse(notification sqlc.Notification) NotificationResponse {
	userID := ""
	if notification.UserID.Valid {
		userID = notification.UserID.String
	}
	var analysisID *string
	if notification.AnalysisID.Valid {
		id := uuid.UUID(notification.AnalysisID.Bytes).String()
		analysisID = &id
	}
	return NotificationResponse{
		ID:          uuid.UUID(notification.ID.Bytes).String(),
		UserID:      userID,
		AnalysisID:  analysisID,
		Type:        notification.Type,
		Title:       notification.Title,
		Message:     notification.Message,
		ReadAt:      timestamptzPtrToString(notification.ReadAt),
		DismissedAt: timestamptzPtrToString(notification.DismissedAt),
		CreatedAt:   notification.CreatedAt.Time.Format(time.RFC3339),
		Metadata:    jsonbToMap(notification.Metadata),
	}
}

func stringFromText(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return strings.TrimSpace(t.String)
}

func textPtr(v string) pgtype.Text {
	return pgtype.Text{String: v, Valid: true}
}

func textPtrFromPtr(v *string) pgtype.Text {
	if v == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *v, Valid: true}
}

// alertToFinding converts a heuristic alert to a FindingResponse
func alertToFinding(alert sqlc.GetHeuristicAlertsByRootExecIDRow, analysisID string) FindingResponse {
	finding := FindingResponse{
		ID:         alert.AlertID,
		AnalysisID: analysisID,
		Category:   alert.AlertType,
		Title:      formatAlertTitle(alert.AlertType),
		CreatedAt:  timestamptzToString(alert.StartTs),
		References: []interface{}{},
	}

	// Map severity
	if alert.Severity.Valid {
		finding.Severity = alert.Severity.String
	} else {
		finding.Severity = "medium"
	}

	// Parse details JSON if available
	if len(alert.Details) > 0 {
		var details map[string]interface{}
		if err := json.Unmarshal(alert.Details, &details); err == nil {
			finding.Metadata = details

			// Extract description from details if available
			if desc, ok := details["description"].(string); ok {
				finding.Description = &desc
			}

			// Extract location/file info
			if file, ok := details["file"].(string); ok {
				finding.Location = &file
			} else if path, ok := details["path"].(string); ok {
				finding.Location = &path
			}

			// Extract code snippet
			if snippet, ok := details["code_snippet"].(string); ok {
				finding.CodeSnippet = &snippet
			}
		}
	}

	// Use reason as description if we don't have one yet
	if finding.Description == nil && alert.Reason.Valid {
		finding.Description = &alert.Reason.String
	}

	// Generate recommendation based on alert type
	rec := generateRecommendation(alert.AlertType, finding.Severity)
	finding.Recommendation = &rec

	return finding
}

// formatAlertTitle converts alert_type to a human-readable title
func formatAlertTitle(alertType string) string {
	switch alertType {
	case "suspicious_network":
		return "Suspicious Network Activity"
	case "malicious_code":
		return "Malicious Code Detected"
	case "data_exfiltration":
		return "Potential Data Exfiltration"
	case "privilege_escalation":
		return "Privilege Escalation Attempt"
	case "credential_access":
		return "Credential Access Detected"
	case "persistence_mechanism":
		return "Persistence Mechanism Found"
	case "command_injection":
		return "Command Injection Detected"
	case "sql_injection":
		return "SQL Injection Detected"
	case "path_traversal":
		return "Path Traversal Detected"
	case "insecure_deserialization":
		return "Insecure Deserialization"
	default:
		// Convert snake_case to Title Case
		parts := strings.Split(strings.ReplaceAll(alertType, "_", " "), " ")
		for i, part := range parts {
			if len(part) > 0 {
				parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
			}
		}
		return "Security Alert: " + strings.Join(parts, " ")
	}
}

// generateRecommendation generates a recommendation based on alert type and severity
func generateRecommendation(alertType, severity string) string {
	baseRec := ""
	switch alertType {
	case "suspicious_network":
		baseRec = "Review network connections and ensure all external communications are legitimate and necessary. Consider implementing network segmentation and firewall rules."
	case "malicious_code":
		baseRec = "Immediately quarantine the affected code and conduct a thorough security review. Scan all related files for malware signatures."
	case "data_exfiltration":
		baseRec = "Investigate data access patterns and implement data loss prevention (DLP) controls. Review access permissions and audit logs."
	case "privilege_escalation":
		baseRec = "Review and restrict privilege escalation mechanisms. Implement principle of least privilege and audit privileged operations."
	case "credential_access":
		baseRec = "Rotate affected credentials immediately. Implement multi-factor authentication and monitor for unauthorized access attempts."
	case "persistence_mechanism":
		baseRec = "Remove unauthorized persistence mechanisms. Review startup scripts, scheduled tasks, and service configurations."
	case "command_injection":
		baseRec = "Sanitize and validate all user inputs. Use parameterized commands and avoid direct shell execution where possible."
	case "sql_injection":
		baseRec = "Use parameterized queries or prepared statements. Validate and sanitize all database inputs."
	case "path_traversal":
		baseRec = "Validate and sanitize file paths. Implement strict input validation and use whitelists for allowed paths."
	case "insecure_deserialization":
		baseRec = "Avoid deserializing untrusted data. Implement integrity checks and use secure serialization formats."
	default:
		baseRec = "Investigate this security alert and take appropriate remediation actions based on your security policies."
	}

	if severity == "critical" || severity == "high" {
		return "URGENT: " + baseRec + " This is a high-priority security issue requiring immediate attention."
	}

	return baseRec
}

func int8PtrFromPtr(v *int64) pgtype.Int8 {
	if v == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *v, Valid: true}
}

func timestamptzPtrToString(t pgtype.Timestamptz) *string {
	if !t.Valid {
		return nil
	}
	s := t.Time.Format(time.RFC3339)
	return &s
}

func timestamptzToString(t pgtype.Timestamptz) string {
	if !t.Valid {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return t.Time.UTC().Format(time.RFC3339)
}

func jsonbToMap(j []byte) map[string]interface{} {
	if len(j) == 0 {
		return nil
	}
	var m map[string]interface{}
	_ = json.Unmarshal(j, &m)
	return m
}

func jsonbToArray(j []byte) []interface{} {
	if len(j) == 0 {
		return nil
	}
	var a []interface{}
	_ = json.Unmarshal(j, &a)
	return a
}
