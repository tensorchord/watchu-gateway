package httpapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/skillsecurity"
	"mime/multipart"
)

type skillSecurityHandlers struct {
	service   *skillsecurity.Service
	uploadDir string
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
	RunnerRunID    *string    `json:"runner_run_id,omitempty"`
	RunnerOutput   *string    `json:"runner_output,omitempty"`
	RunnerExitCode *int32     `json:"runner_exit_code,omitempty"`
	RootExecID     *string    `json:"root_exec_id,omitempty"`
	AgentRunID     *string    `json:"agent_run_id,omitempty"`
}

type SkillSecurityUploadResponse struct {
	ArtifactPath string `json:"artifact_path"`
	SourceRef    string `json:"source_ref"`
	SizeBytes    int64  `json:"size_bytes"`
}

type SkillSummaryResponse struct {
	SourceType   string     `json:"source_type"`
	SourceRef    string     `json:"source_ref"`
	ArtifactPath string     `json:"artifact_path,omitempty"`
	LastRunAt    *time.Time `json:"last_run_at,omitempty"`
	RunCount     int64      `json:"run_count"`
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

// listSkills godoc
// @Summary      List skills
// @Description  Lists unique skills grouped by source_ref and artifact_path.
// @Tags         skill-security
// @Produce      json
// @Param        source_type query string false "Source type"
// @Param        limit query int false "Limit"
// @Success      200  {array}   SkillSummaryResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/skill-security/skills [get]
func (h skillSecurityHandlers) listSkills(c *gin.Context) {
	limit, ok := parseLimitQuery(c, "limit", 50, 1, 500)
	if !ok {
		return
	}
	sourceType := strings.TrimSpace(c.Query("source_type"))

	summaries, err := h.service.ListSkills(c.Request.Context(), sourceType, int32(limit))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]SkillSummaryResponse, 0, len(summaries))
	for _, s := range summaries {
		resp = append(resp, SkillSummaryResponse{
			SourceType:   s.SourceType,
			SourceRef:    s.SourceRef,
			ArtifactPath: s.ArtifactPath,
			LastRunAt:    s.LastRunAt,
			RunCount:     s.RunCount,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// getSkillRuns godoc
// @Summary      Get skill runs
// @Description  Retrieves all runs for a specific skill identified by source_ref.
// @Tags         skill-security
// @Produce      json
// @Param        source_ref query string true "Source ref"
// @Param        artifact_path query string false "Artifact path"
// @Success      200  {array}   SkillSecurityRunResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/skill-security/skills/runs [get]
func (h skillSecurityHandlers) getSkillRuns(c *gin.Context) {
	sourceRef := strings.TrimSpace(c.Query("source_ref"))
	if sourceRef == "" {
		respondError(c, http.StatusBadRequest, "validation_failed", "source_ref is required", nil)
		return
	}
	artifactPath := strings.TrimSpace(c.Query("artifact_path"))

	runs, err := h.service.GetSkillRuns(c.Request.Context(), sourceRef, artifactPath)
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

// uploadSkillSecurityArtifact godoc
// @Summary      Upload skill artifact
// @Description  Uploads a skill archive and returns its server-side path.
// @Tags         skill-security
// @Accept       multipart/form-data
// @Produce      json
// @Param        file formData file true "Skill archive"
// @Success      200  {object}  SkillSecurityUploadResponse
// @Failure      400  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /api/v1/skill-security/uploads [post]
func (h skillSecurityHandlers) uploadArtifact(c *gin.Context) {
	if strings.TrimSpace(h.uploadDir) == "" {
		respondError(c, http.StatusServiceUnavailable, "uploads_disabled", "skill uploads are not configured", nil)
		return
	}

	if err := os.MkdirAll(h.uploadDir, 0o777); err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}
	_ = os.Chmod(h.uploadDir, 0o777)

	form, err := c.MultipartForm()
	if err != nil || form == nil || len(form.File) == 0 {
		file, fileErr := c.FormFile("file")
		if fileErr != nil {
			respondError(c, http.StatusBadRequest, "bad_request", "file is required", nil)
			return
		}

		filename := strings.TrimSpace(filepath.Base(file.Filename))
		if filename == "" || filename == "." || filename == string(filepath.Separator) {
			filename = "skill.zip"
		}

		target := filepath.Join(h.uploadDir, fmt.Sprintf("%s-%s", uuid.NewString(), filename))
		if err := c.SaveUploadedFile(file, target); err != nil {
			respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
			return
		}
		_ = os.Chmod(target, 0o666)

		c.JSON(http.StatusOK, SkillSecurityUploadResponse{
			ArtifactPath: target,
			SourceRef:    filename,
			SizeBytes:    file.Size,
		})
		return
	}

	fileHeaders := make([]*multipart.FileHeader, 0, len(form.File))
	for _, files := range form.File {
		fileHeaders = append(fileHeaders, files...)
	}
	if len(fileHeaders) == 0 {
		respondError(c, http.StatusBadRequest, "bad_request", "file is required", nil)
		return
	}

	rootName := ""
	if form != nil {
		if values, ok := form.Value["root_name"]; ok && len(values) > 0 {
			rootName = cleanUploadPath(values[0])
		}
	}

	hasPath := false
	for _, file := range fileHeaders {
		if strings.Contains(file.Filename, "/") || strings.Contains(file.Filename, "\\") {
			hasPath = true
			break
		}
	}

	if len(fileHeaders) == 1 && !hasPath {
		file := fileHeaders[0]
		filename := strings.TrimSpace(filepath.Base(file.Filename))
		if filename == "" || filename == "." || filename == string(filepath.Separator) {
			filename = "skill.zip"
		}
		target := filepath.Join(h.uploadDir, fmt.Sprintf("%s-%s", uuid.NewString(), filename))
		if err := c.SaveUploadedFile(file, target); err != nil {
			respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
			return
		}
		c.JSON(http.StatusOK, SkillSecurityUploadResponse{
			ArtifactPath: target,
			SourceRef:    filename,
			SizeBytes:    file.Size,
		})
		return
	}

	baseDir := filepath.Join(h.uploadDir, uuid.NewString())
	if err := os.MkdirAll(baseDir, 0o777); err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}
	_ = os.Chmod(baseDir, 0o777)

	var totalSize int64
	topLevel := ""
	consistentTop := true
	for _, file := range fileHeaders {
		rel := cleanUploadPath(file.Filename)
		if rel == "" {
			continue
		}
		if rootName != "" && !strings.HasPrefix(rel, rootName+"/") {
			rel = path.Join(rootName, rel)
		}
		parts := strings.Split(rel, "/")
		if len(parts) > 1 {
			if topLevel == "" {
				topLevel = parts[0]
			} else if topLevel != parts[0] {
				consistentTop = false
			}
		} else {
			consistentTop = false
		}

		target, err := safeJoin(baseDir, rel)
		if err != nil {
			respondError(c, http.StatusBadRequest, "bad_request", err.Error(), nil)
			return
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
			respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
			return
		}
		_ = os.Chmod(filepath.Dir(target), 0o777)
		if err := saveUploadedFile(file, target); err != nil {
			respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
			return
		}
		totalSize += file.Size
	}

	// Validate: must be a single top-level folder
	if topLevel == "" || !consistentTop {
		respondError(c, http.StatusBadRequest, "invalid_upload", "Upload must contain exactly one top-level folder (the skill folder)", nil)
		return
	}

	artifactPath := filepath.Join(baseDir, topLevel)
	sourceRef := topLevel

	c.JSON(http.StatusOK, SkillSecurityUploadResponse{
		ArtifactPath: artifactPath,
		SourceRef:    sourceRef,
		SizeBytes:    totalSize,
	})
}

func registerSkillSecurityRoutes(group *gin.RouterGroup, service *skillsecurity.Service, uploadDir string) {
	if service == nil {
		return
	}
	h := skillSecurityHandlers{service: service, uploadDir: uploadDir}
	securityGroup := group.Group("/skill-security")
	securityGroup.POST("/runs", h.createRun)
	securityGroup.GET("/runs", h.listRuns)
	securityGroup.GET("/runs/:id", h.getRun)
	securityGroup.GET("/skills", h.listSkills)
	securityGroup.GET("/skills/runs", h.getSkillRuns)
	securityGroup.POST("/uploads", h.uploadArtifact)
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
		RunnerRunID:    stringPtrFromText(run.RunnerRunID),
		RunnerOutput:   stringPtrFromText(run.RunnerOutput),
		RunnerExitCode: int32PtrFromInt4(run.RunnerExitCode),
		RootExecID:     stringPtrFromText(run.RootExecID),
		AgentRunID:     uuidPtrFromUUID(run.AgentRunID),
	}
}

func cleanUploadPath(name string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	clean := path.Clean(normalized)
	clean = strings.TrimPrefix(clean, "./")
	if clean == "." || clean == "" || strings.HasPrefix(clean, "..") {
		return ""
	}
	return clean
}

func safeJoin(base, rel string) (string, error) {
	target := filepath.Join(base, filepath.FromSlash(rel))
	baseClean := filepath.Clean(base) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), baseClean) {
		return "", fmt.Errorf("invalid upload path: %s", rel)
	}
	return target, nil
}

func saveUploadedFile(file *multipart.FileHeader, target string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}
	_ = os.Chmod(target, 0o666)
	return nil
}
