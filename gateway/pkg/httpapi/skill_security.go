package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/skillsecurity"
)

type skillSecurityHandlers struct {
	service *skillsecurity.Service
}

type SkillSecurityRunCreateRequest struct {
	SourceType     string `json:"source_type" binding:"required"`
	SourceRef      string `json:"source_ref" binding:"required"`
	RunnerMode     string `json:"runner_mode" binding:"required"`
	AgentType      string `json:"agent_type"`
	PromptStrategy string `json:"prompt_strategy"`
	PromptInput    string `json:"prompt_input"`
	ResolvedRef    string `json:"resolved_ref"`
	ArtifactPath   string `json:"artifact_path"`
}

type SkillSecurityRunResponse struct {
	ID             string     `json:"id"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	SourceType     string     `json:"source_type"`
	SourceRef      string     `json:"source_ref"`
	ResolvedRef    *string    `json:"resolved_ref,omitempty"`
	ArtifactPath   *string    `json:"artifact_path,omitempty"`
	AgentType      string     `json:"agent_type"`
	RunnerMode     string     `json:"runner_mode"`
	PromptStrategy string     `json:"prompt_strategy"`
	PromptInput    *string    `json:"prompt_input,omitempty"`
	Status         string     `json:"status"`
	Error          *string    `json:"error,omitempty"`
	RootExecID     *string    `json:"root_exec_id,omitempty"`
	AgentRunID     *string    `json:"agent_run_id,omitempty"`
}

// createSkillSecurityRun godoc
// @Summary      Create skill security run
// @Description  Creates a skill security run and triggers the runner.
// @Tags         skill-security
// @Accept       json
// @Produce      json
// @Param        body body      SkillSecurityRunCreateRequest true "Run creation request"
// @Success      200  {object}  SkillSecurityRunResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/skill-security/runs [post]
func (h skillSecurityHandlers) createRun(c *gin.Context) {
	var req SkillSecurityRunCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}

	run, err := h.service.CreateRun(c.Request.Context(), skillsecurity.CreateRunInput{
		SourceType:     req.SourceType,
		SourceRef:      req.SourceRef,
		ResolvedRef:    req.ResolvedRef,
		ArtifactPath:   req.ArtifactPath,
		AgentType:      req.AgentType,
		RunnerMode:     req.RunnerMode,
		PromptStrategy: req.PromptStrategy,
		PromptInput:    req.PromptInput,
	})
	if err != nil {
		if errors.Is(err, skillsecurity.ErrRunnerNotConfigured) {
			respondError(c, http.StatusServiceUnavailable, "runner_unavailable", err.Error(), nil)
			return
		}
		respondError(c, http.StatusBadGateway, "runner_error", err.Error(), nil)
		return
	}

	c.JSON(http.StatusOK, convertSkillSecurityRun(run))
}

// getSkillSecurityRun godoc
// @Summary      Get skill security run
// @Description  Retrieves a skill security run by ID.
// @Tags         skill-security
// @Produce      json
// @Param        id path string true "Run ID"
// @Success      200  {object}  SkillSecurityRunResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /api/v1/skill-security/runs/{id} [get]
func (h skillSecurityHandlers) getRun(c *gin.Context) {
	idStr := strings.TrimSpace(c.Param("id"))
	if idStr == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "id is required", nil)
		return
	}
	uid, err := uuid.Parse(idStr)
	if err != nil {
		respondError(c, http.StatusBadRequest, "validation_failed", "id must be a valid UUID", nil)
		return
	}

	run, err := h.service.GetRun(c.Request.Context(), pgtype.UUID{Bytes: uid, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, http.StatusNotFound, "not_found", "run not found", nil)
			return
		}
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	c.JSON(http.StatusOK, convertSkillSecurityRun(run))
}

// listSkillSecurityRuns godoc
// @Summary      List skill security runs
// @Description  Lists skill security runs with optional filters.
// @Tags         skill-security
// @Produce      json
// @Param        status query string false "Run status"
// @Param        source_type query string false "Source type"
// @Param        limit query int false "Limit"
// @Param        offset query int false "Offset"
// @Success      200  {array}   SkillSecurityRunResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/skill-security/runs [get]
func (h skillSecurityHandlers) listRuns(c *gin.Context) {
	limit, ok := parseLimitQuery(c, "limit", 50, 1, 500)
	if !ok {
		return
	}
	offsetStr := c.DefaultQuery("offset", "0")
	offsetVal, err := strconv.Atoi(offsetStr)
	if err != nil || offsetVal < 0 {
		respondError(c, http.StatusBadRequest, "validation_failed", "offset must be a non-negative integer", nil)
		return
	}

	status := strings.TrimSpace(c.Query("status"))
	sourceType := strings.TrimSpace(c.Query("source_type"))

	runs, err := h.service.ListRuns(c.Request.Context(), status, sourceType, limit, int32(offsetVal))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]SkillSecurityRunResponse, 0, len(runs))
	for _, run := range runs {
		resp = append(resp, convertSkillSecurityRun(run))
	}
	c.JSON(http.StatusOK, resp)
}

func registerSkillSecurityRoutes(group *gin.RouterGroup, service *skillsecurity.Service) {
	if service == nil {
		return
	}
	h := skillSecurityHandlers{service: service}
	securityGroup := group.Group("/skill-security")
	securityGroup.POST("/runs", h.createRun)
	securityGroup.GET("/runs", h.listRuns)
	securityGroup.GET("/runs/:id", h.getRun)
}

func convertSkillSecurityRun(run sqlc.SkillSecurityRun) SkillSecurityRunResponse {
	return SkillSecurityRunResponse{
		ID:             uuidStringFromUUID(run.ID),
		CreatedAt:      timePtrFromTimestamptz(run.CreatedAt),
		UpdatedAt:      timePtrFromTimestamptz(run.UpdatedAt),
		SourceType:     run.SourceType,
		SourceRef:      run.SourceRef,
		ResolvedRef:    stringPtrFromText(run.ResolvedRef),
		ArtifactPath:   stringPtrFromText(run.ArtifactPath),
		AgentType:      run.AgentType,
		RunnerMode:     run.RunnerMode,
		PromptStrategy: run.PromptStrategy,
		PromptInput:    stringPtrFromText(run.PromptInput),
		Status:         run.Status,
		Error:          stringPtrFromText(run.Error),
		RootExecID:     stringPtrFromText(run.RootExecID),
		AgentRunID:     uuidPtrFromUUID(run.AgentRunID),
	}
}
