package securityinsight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/llmclient"
	"github.com/tensorchord/watchu/gateway/pkg/promptinjection"
	"github.com/tensorchord/watchu/gateway/pkg/threatinsight"
)

// Service provides unified security insight capabilities including
// prompt injection detection and threat analysis
type Service struct {
	queries        *sqlc.Queries
	promptSvc      *promptinjection.Service
	threatDetector threatinsight.Detector
	threatModel    string
	llmClient      *llmclient.Client
	logger         *slog.Logger
}

var ErrThreatInsightNotInitialized = errors.New("threat insight not initialized")

// Options configures the security insight service
type Options struct {
	PromptInjectionEnabled           bool
	PromptInjectionAPIBase           string
	PromptInjectionAPIKey            string
	PromptInjectionModel             string
	PromptInjectionMode              string
	PromptInjectionTimeout           time.Duration
	PromptInjectionMaxTokens         int
	PromptInjectionBatchSize         int
	PromptInjectionMaxRetries        int
	PromptInjectionSampleRate        float64
	PromptInjectionMaxQPS            float64
	PromptInjectionMaxPromptLen      int
	PromptInjectionStripTools        bool
	PromptInjectionExtractUser       bool
	PromptInjectionEvidenceVerbosity string
	PromptInjectionEvidenceMaxChars  int

	ThreatInsightEnabled bool
	ThreatInsightBaseURL string
	ThreatInsightAPIKey  string
	ThreatInsightModel   string
	ThreatInsightTimeout time.Duration
}

// NewService creates a new unified security insight service
func NewService(queries *sqlc.Queries, opts Options, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}

	promptSvc := promptinjection.NewService(queries, promptinjection.Options{
		Enabled:           opts.PromptInjectionEnabled,
		APIBase:           opts.PromptInjectionAPIBase,
		APIKey:            opts.PromptInjectionAPIKey,
		Model:             opts.PromptInjectionModel,
		Mode:              opts.PromptInjectionMode,
		Timeout:           opts.PromptInjectionTimeout,
		MaxTokens:         opts.PromptInjectionMaxTokens,
		BatchSize:         opts.PromptInjectionBatchSize,
		MaxRetries:        opts.PromptInjectionMaxRetries,
		SampleRate:        opts.PromptInjectionSampleRate,
		MaxQPS:            opts.PromptInjectionMaxQPS,
		MaxPromptLength:   opts.PromptInjectionMaxPromptLen,
		StripToolCalls:    opts.PromptInjectionStripTools,
		ExtractUserPrompt: opts.PromptInjectionExtractUser,
		EvidenceVerbosity: opts.PromptInjectionEvidenceVerbosity,
		EvidenceMaxChars:  opts.PromptInjectionEvidenceMaxChars,
	}, logger)

	var threatDetector threatinsight.Detector
	var threatModel string
	var llmClient *llmclient.Client
	if opts.ThreatInsightEnabled {
		var err error
		threatDetector, threatModel, err = initThreatInsight(queries, opts, logger)
		if err != nil {
			logger.Warn("threat insight disabled", slog.String("reason", err.Error()))
		} else {
			// Initialize LLM client for agent insight extraction
			llmClient = llmclient.NewClient(opts.ThreatInsightBaseURL, opts.ThreatInsightAPIKey, opts.ThreatInsightTimeout)
		}
	}

	return &Service{
		queries:        queries,
		promptSvc:      promptSvc,
		threatDetector: threatDetector,
		threatModel:    threatModel,
		llmClient:      llmClient,
		logger:         logger,
	}, nil
}

// DetectPromptInjection runs prompt injection detection for a host within a time window
func (s *Service) DetectPromptInjection(ctx context.Context, host string, since, until time.Time) error {
	if s.promptSvc == nil {
		return fmt.Errorf("prompt injection detection not initialized")
	}
	return s.promptSvc.Run(ctx, host, since, until)
}

// GetThreatAnalysis retrieves the latest threat analysis result for a specific skill_analysis
// It checks for unified event first, then falls back to aggregating static + dynamic events
func (s *Service) GetThreatAnalysis(ctx context.Context, analysisID pgtype.UUID) (*threatinsight.AnalysisResult, error) {
	// Query all security events for this analysis
	events, err := s.queries.GetSecurityEventsByAnalysisID(ctx, analysisID)
	if err != nil {
		return nil, err
	}

	// Check for unified event first - return directly if exists
	for _, event := range events {
		if event.SourceType == "unified" {
			return s.buildThreatResultFromEvent(&event)
		}
	}

	// No unified event exists - need to aggregate
	// Separate static and dynamic events
	var staticEvents, dynamicEvents []sqlc.SecurityEvent
	for _, event := range events {
		if event.SourceType == "static" {
			staticEvents = append(staticEvents, event)
		} else if event.SourceType == "dynamic" {
			dynamicEvents = append(dynamicEvents, event)
		}
	}

	// If no events at all, return default "no threats" result
	if len(staticEvents) == 0 && len(dynamicEvents) == 0 {
		return s.getDefaultNoThreatResult(ctx, analysisID)
	}

	// If only dynamic events exist and they represent completed analysis (not placeholders)
	// This is common when static analysis doesn't detect threats or isn't applicable
	if len(staticEvents) == 0 && len(dynamicEvents) > 0 {
		// Check if the dynamic event has real analysis data (severity is set)
		dynamicEvent := dynamicEvents[0]
		if dynamicEvent.Severity != "" {
			s.logger.Info("only dynamic analysis available, returning dynamic result",
				slog.String("analysis_id", analysisID.String()),
				slog.String("severity", dynamicEvent.Severity))
			return s.buildThreatResultFromEvent(&dynamicEvent)
		}
	}

	// If only static events exist, return static result
	if len(staticEvents) > 0 && len(dynamicEvents) == 0 {
		staticEvent := staticEvents[0]
		if staticEvent.Severity != "" {
			s.logger.Info("only static analysis available, returning static result",
				slog.String("analysis_id", analysisID.String()),
				slog.String("severity", staticEvent.Severity))
			return s.buildThreatResultFromEvent(&staticEvent)
		}
	}

	// If events exist but both static and dynamic haven't completed yet
	// Return "analyzing" status to indicate work is in progress
	if len(staticEvents) == 0 || len(dynamicEvents) == 0 {
		return &threatinsight.AnalysisResult{
			ThreatLevel:     0,
			ThreatType:      "pending",
			Confidence:      0,
			Summary:         "Analysis in progress",
			Details:         "Waiting for security analysis to complete",
			Recommendations: []string{},
			Evidence:        []map[string]interface{}{},
			Status:          "analyzing",
		}, nil
	}

	// Both types exist - create unified result with LLM
	return s.createUnifiedAnalysis(ctx, analysisID, staticEvents, dynamicEvents)
}

// getDefaultNoThreatResult returns a default "no threats" result when no security events exist
func (s *Service) getDefaultNoThreatResult(ctx context.Context, analysisID pgtype.UUID) (*threatinsight.AnalysisResult, error) {
	rootExecID := ""
	if analysis, err := s.queries.GetSaaSSkillAnalysisByID(ctx, analysisID); err == nil {
		if analysis.RootExecID.Valid {
			rootExecID = analysis.RootExecID.String
		}
	}

	result := &threatinsight.AnalysisResult{
		ThreatLevel:     1,
		ThreatType:      "none",
		Confidence:      1.0,
		Summary:         "No security threats detected",
		Details:         "No telemetry events found for this analysis. Static analysis completed with no issues.",
		Recommendations: []string{},
		Evidence:        []map[string]interface{}{},
		Status:          "ready",
	}

	// Save as dynamic event for consistency
	if saveErr := threatinsight.SaveAnalysisResult(ctx, s.queries, rootExecID, analysisID, result); saveErr != nil {
		s.logger.Warn("failed to save default threat analysis result",
			slog.String("analysis_id", analysisID.String()),
			slog.String("error", saveErr.Error()))
	}

	return result, nil
}

// createUnifiedAnalysis creates a unified threat analysis using LLM when both static and dynamic events exist
func (s *Service) createUnifiedAnalysis(ctx context.Context, analysisID pgtype.UUID, staticEvents, dynamicEvents []sqlc.SecurityEvent) (*threatinsight.AnalysisResult, error) {
	var result *threatinsight.AnalysisResult

	// Call LLM to generate unified result if available
	if s.llmClient != nil {
		// Build input data for LLM from both event types
		staticData := s.buildEventDataForLLM(staticEvents)
		dynamicData := s.buildEventDataForLLM(dynamicEvents)

		// Build the aggregation prompt
		prompt := s.buildAggregationPrompt(staticData, dynamicData)

		response, err := s.llmClient.Complete(ctx, "glm-4.7", prompt, 0.3, 2048)
		if err != nil {
			s.logger.Error("LLM call failed for unified analysis, using smart aggregation",
				slog.String("analysis_id", analysisID.String()),
				slog.String("error", err.Error()))
			result = s.smartAggregate(staticEvents, dynamicEvents)
		} else {
			// Parse LLM response
			parsedResult, err := s.parseLLMResponse(response)
			if err != nil {
				s.logger.Error("Failed to parse LLM response, using smart aggregation",
					slog.String("analysis_id", analysisID.String()),
					slog.String("error", err.Error()))
				result = s.smartAggregate(staticEvents, dynamicEvents)
			} else {
				result = parsedResult
			}
		}
	} else {
		// LLM client not available - use smart aggregation
		s.logger.Warn("LLM client not available, using smart aggregation",
			slog.String("analysis_id", analysisID.String()))
		result = s.smartAggregate(staticEvents, dynamicEvents)
	}

	// Save unified result as a new security_event
	rootExecID := ""
	if analysis, err := s.queries.GetSaaSSkillAnalysisByID(ctx, analysisID); err == nil {
		if analysis.RootExecID.Valid {
			rootExecID = analysis.RootExecID.String
		}
	}

	if saveErr := s.saveUnifiedEvent(ctx, analysisID, rootExecID, result); saveErr != nil {
		s.logger.Warn("failed to save unified event",
			slog.String("analysis_id", analysisID.String()),
			slog.String("error", saveErr.Error()))
	}

	return result, nil
}

// smartAggregate creates a unified result by intelligently combining static and dynamic events
// It prioritizes static threats and filters out contradictory "no threats" messages
func (s *Service) smartAggregate(staticEvents, dynamicEvents []sqlc.SecurityEvent) *threatinsight.AnalysisResult {
	events := append(staticEvents, dynamicEvents...)

	var (
		maxThreatLevel      int
		primaryThreatType   string
		threatTypes         []string
		allEvidence         []map[string]interface{}
		allRecommendations  []string
		summaries           []string
		details             []string
		highestSeverity     string
		analysisStatus      string
	)

	// Find the highest threat level and collect all data
	for _, event := range events {
		severity := event.Severity
		threatLevel := severityToThreatLevel(severity)

		// Track highest threat level and its associated threat type
		if threatLevel > maxThreatLevel {
			maxThreatLevel = threatLevel
			// Capture the threat type from the highest severity event
			if event.Category.Valid {
				primaryThreatType = event.Category.String
			}
		}

		// Track highest severity for description
		if severityCompare(severity, highestSeverity) > 0 {
			highestSeverity = severity
		}

		// Collect threat types
		if event.Category.Valid {
			threatTypes = append(threatTypes, event.Category.String)
		}

		// Collect evidence
		if len(event.Evidence) > 0 {
			var evidence []map[string]interface{}
			if err := json.Unmarshal(event.Evidence, &evidence); err == nil && len(evidence) > 0 {
				allEvidence = append(allEvidence, evidence...)
			}
		}

		if analysisStatus == "" && event.SourceType == "dynamic" {
			if event.ThreatAnalysisStatus.Valid && event.ThreatAnalysisStatus.String != "" {
				analysisStatus = event.ThreatAnalysisStatus.String
			} else if len(event.TelemetrySummary) > 0 {
				var telemetry map[string]interface{}
				if err := json.Unmarshal(event.TelemetrySummary, &telemetry); err == nil {
					if statusRaw, ok := telemetry["analysis_status"]; ok {
						if statusText, ok := statusRaw.(string); ok && statusText != "" {
							analysisStatus = statusText
						}
					}
				}
			}
		}

		// Collect recommendations
		if len(event.Recommendations) > 0 {
			var recommendations []string
			if err := json.Unmarshal(event.Recommendations, &recommendations); err == nil && len(recommendations) > 0 {
				allRecommendations = append(allRecommendations, recommendations...)
			}
		}

		// Collect summaries - skip info/none severity to avoid contradictions
		// This prevents "threats detected; No threats detected" contradictions
		if event.Title != "" && event.Severity != "info" && event.Severity != "none" {
			summaries = append(summaries, event.Title)
		}
		if event.Description.Valid {
			details = append(details, event.Description.String)
		}
		if event.AiGeneratedSummary.Valid {
			details = append(details, event.AiGeneratedSummary.String)
		}
	}

	// Build unique threat types
	uniqueThreatTypes := make(map[string]bool)
	for _, tt := range threatTypes {
		uniqueThreatTypes[tt] = true
	}
	var finalThreatTypes []string
	for tt := range uniqueThreatTypes {
		finalThreatTypes = append(finalThreatTypes, tt)
	}

	// Build summary from all summaries
	summary := "Security analysis completed"
	if len(summaries) > 0 {
		summary = strings.Join(summaries, "; ")
	}

	// Build details from all details
	detailText := ""
	if len(details) > 0 {
		detailText = strings.Join(details, "\n\n")
	}
	if detailText == "" && highestSeverity != "" {
		detailText = fmt.Sprintf("Analysis completed with %s severity findings.", highestSeverity)
	}

	// Build recommendations from all recommendations
	uniqueRecommendations := make(map[string]bool)
	for _, rec := range allRecommendations {
		uniqueRecommendations[rec] = true
	}
	var finalRecommendations []string
	for rec := range uniqueRecommendations {
		finalRecommendations = append(finalRecommendations, rec)
	}

	// Use the threat type from the highest severity event (already captured in loop)
	// If not set (e.g., all events have no category), fall back to first available or "security"
	if primaryThreatType == "" {
		if len(finalThreatTypes) > 0 {
			primaryThreatType = finalThreatTypes[0]
		} else {
			primaryThreatType = "security"
		}
	}

	// Calculate confidence based on number and severity of findings
	confidence := 1.0
	if len(events) > 0 {
		// More events with high severity = higher confidence
		severityScore := map[string]int{
			"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0,
		}
		totalScore := 0
		for _, e := range events {
			if score, ok := severityScore[e.Severity]; ok {
				totalScore += score
			}
		}
		avgScore := float64(totalScore) / float64(len(events))
		confidence = avgScore / 5.0 // Normalize to 0-1
	}

	result := &threatinsight.AnalysisResult{
		ThreatLevel:     maxThreatLevel,
		ThreatType:      primaryThreatType,
		Confidence:      confidence,
		Summary:         summary,
		Details:         detailText,
		Recommendations: finalRecommendations,
		Evidence:        allEvidence,
	}
	if analysisStatus != "" {
		result.Status = analysisStatus
	} else {
		result.Status = "ready"
	}

	return result
}

// buildEventDataForLLM converts security events to structured data for LLM prompt
func (s *Service) buildEventDataForLLM(events []sqlc.SecurityEvent) map[string]interface{} {
	if len(events) == 0 {
		return map[string]interface{}{
			"has_findings": false,
			"threat_level": 1,
		}
	}

	// Get the highest severity event
	var highestEvent *sqlc.SecurityEvent
	maxThreatLevel := 0
	for i := range events {
		threatLevel := severityToThreatLevel(events[i].Severity)
		if threatLevel > maxThreatLevel {
			maxThreatLevel = threatLevel
			highestEvent = &events[i]
		}
	}

	data := map[string]interface{}{
		"has_findings": true,
		"threat_level": maxThreatLevel,
	}

	if highestEvent != nil {
		if highestEvent.Title != "" {
			data["summary"] = highestEvent.Title
		}
		if highestEvent.Description.Valid {
			data["details"] = highestEvent.Description.String
		}
		if highestEvent.Category.Valid {
			data["threat_type"] = highestEvent.Category.String
		}
		if len(highestEvent.Evidence) > 0 {
			var evidence []map[string]interface{}
			if err := json.Unmarshal(highestEvent.Evidence, &evidence); err == nil {
				data["evidence"] = evidence
			}
		}
		if len(highestEvent.Recommendations) > 0 {
			var recommendations []string
			if err := json.Unmarshal(highestEvent.Recommendations, &recommendations); err == nil {
				data["recommendations"] = recommendations
			}
		}
	}

	return data
}

// buildAggregationPrompt creates a prompt for LLM to unify static and dynamic analysis results
func (s *Service) buildAggregationPrompt(staticData, dynamicData map[string]interface{}) string {
	staticJSON, _ := json.MarshalIndent(staticData, "  ", "  ")
	dynamicJSON, _ := json.MarshalIndent(dynamicData, "  ", "  ")

	return fmt.Sprintf(`You are a senior security analyst synthesizing multiple security analysis results.

INPUT DATA:
1. Static Analysis (code analysis):
%s

2. Dynamic Analysis (runtime telemetry):
%s

TASK:
Generate a UNIFIED threat assessment that synthesizes both analyses.

CRITICAL RULES:
- If static analysis found threats, the final assessment MUST reflect those threats
- DO NOT say "No threats detected" if static analysis found actual threats
- Combine evidence from both sources into a coherent narrative
- Use the HIGHEST threat level from either source as the final threat_level
- Set threat_type based on static analysis if it identified specific threat types
- Recommendations should address findings from BOTH sources
- Summary must be consistent - no contradictions like "threats detected; no threats"

OUTPUT FORMAT (JSON only):
{
  "threat_level": int (1-5),
  "threat_type": string,
  "confidence": float (0-1),
  "summary": string (unified summary without contradictions),
  "details": string (comprehensive analysis),
  "recommendations": [string],
  "evidence": [{"type": string, "description": string, "severity": string}]
}

Respond with a single valid JSON object only. Do not surround the output with Markdown or explanatory text.`, string(staticJSON), string(dynamicJSON))
}

// parseLLMResponse parses the LLM response into an AnalysisResult
func (s *Service) parseLLMResponse(response string) (*threatinsight.AnalysisResult, error) {
	// Clean up response - remove markdown code blocks if present
	cleaned := response
	if strings.HasPrefix(cleaned, "```json") {
		cleaned = strings.TrimPrefix(cleaned, "```json")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	} else if strings.HasPrefix(cleaned, "```") {
		cleaned = strings.TrimPrefix(cleaned, "```")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	}

	var result threatinsight.AnalysisResult
	if err := json.Unmarshal([]byte(cleaned), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM JSON response: %w", err)
	}

	return &result, nil
}

// saveUnifiedEvent saves the unified analysis result as a security_event with source_type='unified'
func (s *Service) saveUnifiedEvent(ctx context.Context, analysisID pgtype.UUID, rootExecID string, result *threatinsight.AnalysisResult) error {
	// Map threat level to severity
	severity, ok := threatLevelToSeverity[result.ThreatLevel]
	if !ok {
		severity = "info"
	}

	// Convert to JSON
	recommendationsJSON, _ := json.Marshal(result.Recommendations)
	evidenceJSON, _ := json.Marshal(result.Evidence)
	telemetrySummary := map[string]interface{}{
		"threat_level":    result.ThreatLevel,
		"threat_type":     result.ThreatType,
		"confidence":      result.Confidence,
		"root_exec_id":    rootExecID,
		"analysis_status": "ready",
	}
	telemetryJSON, _ := json.Marshal(telemetrySummary)

	confidenceNum := pgtype.Numeric{}
	_ = confidenceNum.Scan(result.Confidence)

	// Build params for upsert
	params := sqlc.UpsertSecurityEventParams{
		AnalysisID:          analysisID,
		SourceType:          "unified",
		Severity:            severity,
		Category:            pgtype.Text{String: result.ThreatType, Valid: result.ThreatType != ""},
		Title:               result.Summary,
		Description:         pgtype.Text{String: result.Details, Valid: true},
		Confidence:          confidenceNum,
		Recommendations:     recommendationsJSON,
		Evidence:            evidenceJSON,
		TelemetrySummary:    telemetryJSON,
		ThreatAnalysisStatus: pgtype.Text{String: "ready", Valid: true},
	}

	// Execute upsert
	_, err := s.queries.UpsertSecurityEvent(ctx, params)
	return err
}

// severityCompare returns positive if s1 is higher severity than s2
func severityCompare(s1, s2 string) int {
	severityOrder := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0,
	}
	v1, ok1 := severityOrder[s1]
	if !ok1 {
		v1 = 0
	}
	v2, ok2 := severityOrder[s2]
	if !ok2 {
		v2 = 0
	}
	return v1 - v2
}

// buildThreatResultFromEvent converts a security event to a threat analysis result
func (s *Service) buildThreatResultFromEvent(event *sqlc.SecurityEvent) (*threatinsight.AnalysisResult, error) {
	// Map severity back to threat level
	threatLevel := severityToThreatLevel(event.Severity)

	// Determine threat type
	var threatType string
	if event.SourceType == "static" && len(event.TelemetrySummary) > 0 {
		// Static analysis may have telemetry summary with threat type
		var telemetry map[string]interface{}
		if err := json.Unmarshal(event.TelemetrySummary, &telemetry); err == nil {
			if tt, ok := telemetry["threat_type"].(string); ok {
				threatType = tt
			}
		}
	}
	if threatType == "" && event.Category.Valid {
		threatType = event.Category.String
	}

	// Build confidence from decimal
	confidence := 1.0
	if event.Confidence.Valid {
		var f float64
		if err := event.Confidence.Scan(&f); err == nil {
			confidence = f
		}
	}

	// Build details: use description first, then AI summary
	details := coalesceString(event.Description, event.AiGeneratedSummary)
	if details == "" && event.SourceType == "static" {
		details = "Static code analysis identified potential security issues in the skill code."
	}

	result := &threatinsight.AnalysisResult{
		ThreatLevel: threatLevel,
		ThreatType:  threatType,
		Confidence:  confidence,
		Summary:     event.Title,
		Details:     details,
		Status:      "ready",
	}

	// Parse recommendations from JSONB
	if len(event.Recommendations) > 0 {
		var recommendations []string
		if err := json.Unmarshal(event.Recommendations, &recommendations); err == nil {
			result.Recommendations = recommendations
		}
	}

	// Parse evidence from JSONB
	if len(event.Evidence) > 0 {
		var evidence []map[string]interface{}
		if err := json.Unmarshal(event.Evidence, &evidence); err == nil {
			result.Evidence = evidence
		}
	}

	return result, nil
}

// severityToThreatLevel maps severity string to threat level (1-5)
func severityToThreatLevel(severity string) int {
	switch severity {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0 // none
	}
}

// coalesceString returns the first non-empty string
func coalesceString(a, b pgtype.Text) string {
	if a.Valid && a.String != "" {
		return a.String
	}
	if b.Valid && b.String != "" {
		return b.String
	}
	return ""
}

// GetThreatAnalysisByRootExecID retrieves threat analysis by root_exec_id (fallback method)
func (s *Service) GetThreatAnalysisByRootExecID(ctx context.Context, rootExecID string) (*threatinsight.AnalysisResult, error) {
	rootExecIDText := pgtype.Text{String: rootExecID, Valid: true}
	row, err := s.queries.GetLatestSecurityAnalysisByRootExecID(ctx, rootExecIDText)
	if err != nil {
		return nil, err
	}

	// Convert database row to AnalysisResult
	result := &threatinsight.AnalysisResult{
		ThreatLevel: int(row.ThreatLevel.Int32),
		ThreatType:  row.ThreatType.String,
		Confidence:  row.Confidence.Float64,
		Summary:     row.Summary.String,
		Details:     row.Details.String,
	}

	// Parse recommendations from JSONB
	if len(row.Recommendations) > 0 {
		var recommendations []string
		if err := json.Unmarshal(row.Recommendations, &recommendations); err == nil {
			result.Recommendations = recommendations
		}
	}

	// Parse evidence from JSONB
	if len(row.Evidence) > 0 {
		var evidence []map[string]interface{}
		if err := json.Unmarshal(row.Evidence, &evidence); err == nil {
			result.Evidence = evidence
		}
	}

	return result, nil
}

// AnalyzeThreatByRootExecID performs threat analysis by root_exec_id (legacy API)
// This doesn't link to a specific skill_analysis, for backward compatibility
func (s *Service) AnalyzeThreatByRootExecID(ctx context.Context, rootExecID string) (*threatinsight.AnalysisResult, error) {
	if s.threatDetector == nil {
		return nil, ErrThreatInsightNotInitialized
	}

	// Check for existing analysis in the last 24 hours
	rootExecIDText := pgtype.Text{String: rootExecID, Valid: true}
	existingResult, err := s.queries.GetLatestSecurityAnalysisByRootExecID(ctx, rootExecIDText)
	if err == nil {
		// Found existing result, check if it's recent (within 24 hours)
		if time.Since(existingResult.AnalyzedAt.Time) < 24*time.Hour {
			s.logger.Info("using cached threat analysis result",
				slog.String("root_exec_id", rootExecID),
				slog.Time("analyzed_at", existingResult.AnalyzedAt.Time))

			// Convert to AnalysisResult and return
			result := &threatinsight.AnalysisResult{
				ThreatLevel: int(existingResult.ThreatLevel.Int32),
				ThreatType:  existingResult.ThreatType.String,
				Confidence:  existingResult.Confidence.Float64,
				Summary:     existingResult.Summary.String,
				Details:     existingResult.Details.String,
			}

			if len(existingResult.Recommendations) > 0 {
				var recommendations []string
				if err := json.Unmarshal(existingResult.Recommendations, &recommendations); err == nil {
					result.Recommendations = recommendations
				}
			}

			if len(existingResult.Evidence) > 0 {
				var evidence []map[string]interface{}
				if err := json.Unmarshal(existingResult.Evidence, &evidence); err == nil {
					result.Evidence = evidence
				}
			}

			return result, nil
		}
		s.logger.Info("existing analysis is stale, performing new analysis",
			slog.String("root_exec_id", rootExecID),
			slog.Duration("age", time.Since(existingResult.AnalyzedAt.Time)))
	}

	// No recent result found, perform new analysis
	s.logger.Info("performing new threat analysis", slog.String("root_exec_id", rootExecID))
	result, err := s.threatDetector.Analyze(ctx, rootExecID)
	if err != nil {
		if llmclient.IsRateLimitError(err) {
			result = &threatinsight.AnalysisResult{
				ThreatLevel:     1,
				ThreatType:      "rate_limited",
				Confidence:      1.0,
				Summary:         "Threat analysis rate limited. Please try again later or contact yuandongxie@tensorchord.ai.",
				Details:         err.Error(),
				Recommendations: []string{"Wait for quota reset or contact yuandongxie@tensorchord.ai"},
				Evidence:        []map[string]interface{}{},
				Status:          "rate_limited",
			}
		} else {
			return nil, err
		}
	}

	if result.Status == "" {
		result.Status = "ready"
	}

	// Save analysis result to database without linking to a specific skill_analysis
	// (for backward compatibility with direct threat analysis calls)
	if saveErr := threatinsight.SaveAnalysisResult(ctx, s.queries, rootExecID, pgtype.UUID{}, result); saveErr != nil {
		s.logger.Warn("failed to save threat analysis result", slog.String("root_exec_id", rootExecID), slog.String("error", saveErr.Error()))
	}

	return result, nil
}

// AnalyzeThreat performs deep threat analysis on a skill analysis
// It first checks if a recent analysis exists in the database (within 24 hours)
// If found, returns the cached result; otherwise, performs new analysis
// Uses correlation_id (analysis_id) for precise per-analysis isolation
func (s *Service) AnalyzeThreat(ctx context.Context, analysisID pgtype.UUID) (*threatinsight.AnalysisResult, error) {
	if s.threatDetector == nil {
		return nil, ErrThreatInsightNotInitialized
	}

	// Check for existing dynamic analysis event in the last 24 hours
	events, err := s.queries.GetSecurityEventsByAnalysisID(ctx, analysisID)
	if err == nil {
		// Find the dynamic analysis event
		for _, event := range events {
			if event.SourceType == "dynamic" {
				// Check if it's recent (within 24 hours)
				if time.Since(event.CreatedAt.Time) < 24*time.Hour {
					s.logger.Info("using cached threat analysis result",
						slog.String("analysis_id", analysisID.String()),
						slog.Time("created_at", event.CreatedAt.Time))

					// Convert to AnalysisResult and return
					threatLevel := severityToThreatLevel(event.Severity)

					// Extract threat type from telemetry summary or category
					var threatType string
					if len(event.TelemetrySummary) > 0 {
						var telemetry map[string]interface{}
						if err := json.Unmarshal(event.TelemetrySummary, &telemetry); err == nil {
							if tt, ok := telemetry["threat_type"].(string); ok {
								threatType = tt
							}
						}
					}
					if threatType == "" && event.Category.Valid {
						threatType = event.Category.String
					}

					// Build confidence from decimal
					confidence := 1.0
					if event.Confidence.Valid {
						var f float64
						if err := event.Confidence.Scan(&f); err == nil {
							confidence = f
						}
					}

					result := &threatinsight.AnalysisResult{
						ThreatLevel: threatLevel,
						ThreatType:  threatType,
						Confidence:  confidence,
						Summary:     event.Title,
						Details:     coalesceString(event.Description, event.AiGeneratedSummary),
					}

					if len(event.Recommendations) > 0 {
						var recommendations []string
						if err := json.Unmarshal(event.Recommendations, &recommendations); err == nil {
							result.Recommendations = recommendations
						}
					}

					if len(event.Evidence) > 0 {
						var evidence []map[string]interface{}
						if err := json.Unmarshal(event.Evidence, &evidence); err == nil {
							result.Evidence = evidence
						}
					}

					return result, nil
				}
				s.logger.Info("existing analysis is stale, performing new analysis",
					slog.String("analysis_id", analysisID.String()),
					slog.Duration("age", time.Since(event.CreatedAt.Time)))
			}
		}
	}

	// Get skill analysis details including skill name for filtering
	analysis, err := s.queries.GetSaaSSkillAnalysisByID(ctx, analysisID)
	if err != nil {
		return nil, fmt.Errorf("failed to get skill analysis: %w", err)
	}

	rootExecID := ""
	if analysis.RootExecID.Valid {
		rootExecID = analysis.RootExecID.String
	}

	// Extract skill name for filtering agent threat reports
	skillName := ""
	if analysis.SkillName.Valid {
		skillName = analysis.SkillName.String
	}

	// Use correlation_id (analysis_id) for precise per-analysis threat analysis
	// This avoids issues when multiple analyses share the same root_exec_id
	correlationID := uuid.UUID(analysisID.Bytes).String()

	// Determine analysis type for context-aware threat detection
	// Skill Security SaaS analyses should skip certain expected patterns like --dangerously-skip-permissions
	analysisType := ""
	if analysis.SkillID.Valid {
		analysisType = "skill_security_saas"
	}

	s.logger.Info("performing new threat analysis using correlation_id",
		slog.String("analysis_id", analysisID.String()),
		slog.String("correlation_id", correlationID),
		slog.String("skill_name", skillName),
		slog.String("root_exec_id", rootExecID),
		slog.String("analysis_type", analysisType))

	result, err := s.threatDetector.AnalyzeByCorrelationID(ctx, correlationID, skillName, analysisType)
	if err != nil {
		if llmclient.IsRateLimitError(err) {
			result = &threatinsight.AnalysisResult{
				ThreatLevel:     1,
				ThreatType:      "rate_limited",
				Confidence:      1.0,
				Summary:         "Threat analysis rate limited. Please try again later or contact yuandongxie@tensorchord.ai.",
				Details:         err.Error(),
				Recommendations: []string{"Wait for quota reset or contact yuandongxie@tensorchord.ai"},
				Evidence:        []map[string]interface{}{},
				Status:          "rate_limited",
			}
		} else {
			return nil, err
		}
	}

	if result.Status == "" {
		result.Status = "ready"
	}

	// Save analysis result to database linked to this skill_analysis (as dynamic event)
	if saveErr := threatinsight.SaveAnalysisResult(ctx, s.queries, rootExecID, analysisID, result); saveErr != nil {
		s.logger.Warn("failed to save threat analysis result",
			slog.String("analysis_id", analysisID.String()),
			slog.String("root_exec_id", rootExecID),
			slog.String("error", saveErr.Error()))
	}

	// Check if static analysis events exist - if so, create unified analysis immediately
	// This ensures unified result is ready when both static and dynamic analyses complete
	allEvents, eventsErr := s.queries.GetSecurityEventsByAnalysisID(ctx, analysisID)
	if eventsErr == nil {
		var staticEvents []sqlc.SecurityEvent
		for _, event := range allEvents {
			if event.SourceType == "static" {
				staticEvents = append(staticEvents, event)
			}
		}
		
		// If static events exist, create unified analysis now
		if len(staticEvents) > 0 {
			s.logger.Info("static analysis exists, creating unified analysis immediately",
				slog.String("analysis_id", analysisID.String()),
				slog.Int("static_events", len(staticEvents)))
			
			// Get the just-saved dynamic event
			var dynamicEvents []sqlc.SecurityEvent
			for _, event := range allEvents {
				if event.SourceType == "dynamic" {
					dynamicEvents = append(dynamicEvents, event)
				}
			}
			
			// Create unified analysis
			unifiedResult, unifiedErr := s.createUnifiedAnalysis(ctx, analysisID, staticEvents, dynamicEvents)
			if unifiedErr != nil {
				s.logger.Warn("failed to create unified analysis",
					slog.String("analysis_id", analysisID.String()),
					slog.String("error", unifiedErr.Error()))
			} else {
				// Return unified result instead of dynamic-only result
				return unifiedResult, nil
			}
		}
	}

	return result, nil
}

// Ready checks if the service is ready for health checks
func (s *Service) Ready(ctx context.Context) error {
	if s.promptSvc != nil {
		return s.promptSvc.Ready(ctx)
	}
	return nil
}

// PromptInjectionService returns the underlying prompt injection service for scheduler
func (s *Service) PromptInjectionService() *promptinjection.Service {
	return s.promptSvc
}

// ExtractAndStore extracts agent threat insights from runner output and stores them
// This analyzes the agent's own execution logs for threat detection messages
func (s *Service) ExtractAndStore(ctx context.Context, skillRunID uuid.UUID, rootExecID, agentType, runnerOutput string) error {
	if runnerOutput == "" {
		s.logger.DebugContext(ctx, "no runner output to extract insights from", "skill_run_id", skillRunID)
		return nil
	}

	if s.llmClient == nil {
		s.logger.DebugContext(ctx, "llm client not initialized, skipping insight extraction", "skill_run_id", skillRunID)
		return nil
	}

	// Use LLM to extract threat insights from runner output
	insights, err := s.extractInsights(ctx, runnerOutput, agentType)
	if err != nil {
		return fmt.Errorf("failed to extract insights: %w", err)
	}

	// If no threats detected, return without error
	if len(insights) == 0 {
		s.logger.DebugContext(ctx, "no threat insights extracted from runner output", "skill_run_id", skillRunID)
		return nil
	}

	// Store insights in agent_threat_reports table
	now := time.Now()

	// Get the actual host from exec_events using rootExecID
	host := "localhost" // default fallback
	if rootExecID != "" {
		if events, err := s.queries.GetEventsByRootExecID(ctx, sqlc.GetEventsByRootExecIDParams{
			RootExecID: pgtype.Text{String: rootExecID, Valid: true},
		}); err == nil && len(events) > 0 {
			host = events[0].Host
		}
	}

	var storedInsights []agentInsight
	for _, insight := range insights {
		id := uuid.New()
		createdJSON, _ := json.Marshal(insight.Evidence)

		// Build metadata with recommendation
		metadata := map[string]interface{}{}
		if insight.Recommendation != "" {
			metadata["recommendation"] = insight.Recommendation
		}
		metadataJSON, _ := json.Marshal(metadata)

		// Build parameters for insert
		params := sqlc.InsertAgentThreatReportParams{
			ID:         pgtype.UUID{Bytes: id, Valid: true},
			CreatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
			UpdatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
			Host:       host,
			RootExecID: textOrNull(rootExecID),
			AgentType:  agentType,
			ThreatType: insight.ThreatType,
			ThreatLevel: int32(insight.ThreatLevel),
			Confidence:  insight.Confidence,
			Title:       insight.Title,
			Description: textOrNull(insight.Description),
			Evidence:    createdJSON,
			Metadata:    metadataJSON,
			Status:      "active",
		}

		if insight.DetectionMethod != "" {
			params.DetectionMethod = textOrNull(insight.DetectionMethod)
		}
		if insight.FilePath != "" {
			params.FilePath = textOrNull(insight.FilePath)
		}
		if insight.CodeSnippet != "" {
			params.CodeSnippet = textOrNull(insight.CodeSnippet)
		}

		if _, err := s.queries.InsertAgentThreatReport(ctx, params); err != nil {
			return fmt.Errorf("failed to insert agent threat report: %w", err)
		}

		s.logger.InfoContext(ctx, "stored agent threat insight",
			"insight_id", id,
			"skill_run_id", skillRunID,
			"threat_type", insight.ThreatType,
			"threat_level", insight.ThreatLevel,
		)

		// Store the insight with ID for later conversion to findings
		insight.ID = id
		storedInsights = append(storedInsights, insight)
	}

	// Convert agent_threat_reports to findings for the associated skill_analysis
	if err := s.convertThreatReportsToFindings(ctx, skillRunID, rootExecID, storedInsights); err != nil {
		s.logger.WarnContext(ctx, "failed to convert threat reports to findings",
			"error", err.Error(),
			"skill_run_id", skillRunID)
			// Don't fail the entire operation if findings conversion fails
	}

	return nil
}

// convertThreatReportsToFindings converts agent threat reports to security_events records (static analysis)
func (s *Service) convertThreatReportsToFindings(ctx context.Context, skillRunID uuid.UUID, rootExecID string, insights []agentInsight) error {
	if len(insights) == 0 {
		return nil
	}

	// Find the associated skill_analysis by ID
	// Note: skillRunID is actually skill_analyses.id, not runner_run_id
	analysis, err := s.queries.GetSkillAnalysisByID(ctx, pgtype.UUID{Bytes: skillRunID, Valid: true})
	if err != nil {
		return fmt.Errorf("failed to find skill analysis: %w", err)
	}

	for _, insight := range insights {
		// Convert threat_level to severity
		severity, ok := threatLevelToSeverity[insight.ThreatLevel]
		if !ok {
			severity = "info" // default fallback (was "secure", but "info" is in the security_events check constraint)
		}

		// Convert evidence to reference links
		var referenceLinksJSON []byte
		if len(insight.Evidence) > 0 {
			// Build structured references from evidence
			references := make([]map[string]interface{}, 0)
			for _, ev := range insight.Evidence {
				ref := map[string]interface{}{
					"type":  stringValue(ev["type"]),
					"title": stringValue(ev["type"]),
					"url":   "",
				}
				if desc, ok := ev["content"]; ok {
					ref["description"] = stringValue(desc)
				}
				references = append(references, ref)
			}
			referenceLinksJSON, _ = json.Marshal(references)
		}

		// Build recommendations array
		recommendations := []string{buildRecommendation(insight)}
		recommendationsJSON, _ := json.Marshal(recommendations)

		// Build metadata
		metadata := map[string]interface{}{
			"detection_method": insight.DetectionMethod,
			"agent_type":       "agent", // indicates this is from agent insights
		}
		metadataJSON, _ := json.Marshal(metadata)

		// Insert security event using UpsertSecurityEvent
		// Use source_type "static" for static analysis findings from agent
		_, err = s.queries.UpsertSecurityEvent(ctx, sqlc.UpsertSecurityEventParams{
			AnalysisID:         analysis.ID,
			SourceType:         "static",
			Severity:           severity,
			Category:           pgtype.Text{String: insight.ThreatType, Valid: true},
			Title:              insight.Title,
			Description:        textOrNull(insight.Description),
			Confidence:         numericFromFloat64(insight.Confidence),
			CodeSnippet:        textOrNull(insight.CodeSnippet),
			FilePath:           textOrNull(insight.FilePath),
			ReferenceLinks:     referenceLinksJSON,
			TelemetrySummary:   []byte("{}"),
			ThreatAnalysisStatus: pgtype.Text{},
			AiGeneratedSummary: pgtype.Text{},
			Recommendations:    recommendationsJSON,
			Evidence:           func() []byte { b, _ := json.Marshal(insight.Evidence); return b }(),
			Metadata:           metadataJSON,
		})
		if err != nil {
			return fmt.Errorf("failed to insert security event: %w", err)
		}

		s.logger.InfoContext(ctx, "created security event from threat report",
			"event_id", "N/A",
			"analysis_id", analysis.ID.String(),
			"severity", severity,
			"category", insight.ThreatType,
		)
	}

	// Create notification for detected threats
	// Only create notification if there are findings with severity >= "high"
	hasCriticalThreats := false
	for _, insight := range insights {
		if insight.ThreatLevel >= 4 { // high or critical
			hasCriticalThreats = true
			break
		}
	}

	if hasCriticalThreats {
		if err := s.createThreatNotification(ctx, analysis.ID.Bytes, analysis.SkillID.Bytes, insights); err != nil {
			s.logger.WarnContext(ctx, "failed to create threat notification",
				"error", err.Error(),
				"analysis_id", analysis.ID.String())
		}
	}

	// Update skill_analyses total_findings and severity_summary
	if err := s.updateAnalysisFindings(ctx, analysis.ID); err != nil {
		s.logger.WarnContext(ctx, "failed to update analysis findings",
			"error", err.Error(),
			"analysis_id", analysis.ID.String())
	}

	return nil
}

// updateAnalysisFindings recalculates and updates total_findings and severity_summary for an analysis
func (s *Service) updateAnalysisFindings(ctx context.Context, analysisID pgtype.UUID) error {
	// Count security events by severity
	events, err := s.queries.GetSaaSSecurityEventsByAnalysisID(ctx, analysisID)
	if err != nil {
		return fmt.Errorf("failed to query security events: %w", err)
	}

	totalFindings := len(events)
	severitySummary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"none":     0,
	}

	for _, e := range events {
		if count, ok := severitySummary[e.Severity]; ok {
			severitySummary[e.Severity] = count + 1
		}
	}

	severityJSON, _ := json.Marshal(severitySummary)

	// Update skill_analyses using the SaaS method
	_, err = s.queries.UpdateSaaSSkillAnalysisFindings(ctx, sqlc.UpdateSaaSSkillAnalysisFindingsParams{
		ID:              analysisID,
		TotalFindings:   pgtype.Int4{Int32: int32(totalFindings), Valid: true},
		SeveritySummary: severityJSON,
	})
	return err
}

// threatLevelToSeverity converts threat level (1-5) to severity string
var threatLevelToSeverity = map[int]string{
	5: "critical",
	4: "high",
	3: "medium",
	2: "low",
	1: "secure",
}

// buildRecommendation creates a recommendation based on the insight
// Uses AI-generated recommendation if available, otherwise falls back to generic advice
func buildRecommendation(insight agentInsight) string {
	// Use AI-generated recommendation if available
	if insight.Recommendation != "" {
		return insight.Recommendation
	}

	// Fallback to generic recommendation based on threat type
	var rec string

	switch insight.ThreatType {
	case "malicious_code", "trojan", "backdoor", "rootkit":
		rec = "Remove or disable this skill immediately. Do not use it in production."
		if insight.FilePath != "" {
			rec += fmt.Sprintf(" Review and remove malicious code from %s.", insight.FilePath)
		}
	case "prompt_injection", "jailbreak", "adversarial_attack":
		rec = "Review and implement input validation and sanitization. Add guardrails to prevent prompt injection attacks."
	case "data_exfiltration", "information_disclosure":
		rec = "Investigate the destination of data exfiltration. Block network access if necessary. Review data handling practices."
	case "injection", "code_execution":
		rec = "Sanitize all user inputs before processing. Use parameterized queries. Avoid eval() and similar dynamic code execution."
	case "ransomware", "crypto_mining", "botnet":
		rec = "CRITICAL: Isolate and disable this skill immediately. Investigate for indicators of compromise. Scan affected systems."
	default:
		rec = "Review this skill for security implications before using in production."
	}

	return rec
}

// stringValue safely extracts a string value from an interface{}
func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", v)
}

// agentInsight represents a single threat insight extracted from agent logs
type agentInsight struct {
	ID              uuid.UUID
	ThreatType      string
	ThreatLevel     int
	Confidence      float64
	Title           string
	Description     string
	Recommendation  string
	Evidence        []map[string]interface{}
	DetectionMethod string
	FilePath        string
	CodeSnippet     string
}

// extractInsights uses LLM to extract threat insights from runner output
func (s *Service) extractInsights(ctx context.Context, runnerOutput, agentType string) ([]agentInsight, error) {
	prompt := s.buildExtractionPrompt(runnerOutput, agentType)

	response, err := s.llmClient.Complete(ctx, s.threatModel, prompt, 0.2, 4096)
	if err != nil {
		return nil, fmt.Errorf("LLM extraction failed: %w", err)
	}

	return s.parseExtractionResponse(response)
}

// buildExtractionPrompt constructs the prompt for extracting threat insights from logs
func (s *Service) buildExtractionPrompt(runnerOutput, agentType string) string {
	promptData := map[string]interface{}{
		"runner_output": runnerOutput,
		"agent_type":    agentType,
	}

	instructions := `You are a security analyst reviewing AI agent execution logs to identify security concerns detected by the agent.

OBJECTIVE:
Extract evidence that the AI agent identified security issues, threats, or suspicious patterns during execution.

WHAT TO LOOK FOR:
1. Explicit security statements:
   - "I detected malicious code", "refusing to execute", "security concern"
   - "This code appears to be/contains", "potentially malicious"

2. Behavioral indicators of threat detection:
   - Agent stopped execution mid-task without clear technical error
   - Agent declined to proceed with specific operations
   - Agent suggested alternative approaches for security reasons

3. Security-related errors or warnings:
   - Messages about unsafe operations, security violations
   - Warnings about specific code patterns (e.g., "reverse shell", "code injection")

4. Contextual evidence:
   - File paths mentioned as suspicious
   - Code snippets quoted as problematic
   - Specific lines or patterns identified

DATA:
- runner_output: Raw agent execution log (may include compilation, dependencies, etc.)
- agent_type: Agent type (e.g., "claude-code")

OUTPUT FORMAT:
Return a JSON object with a "threats" array. Each threat should have:
{
  "threats": [
    {
      "threat_type": "malicious_code|prompt_injection|data_exfiltration|injection|code_execution|path_traversal|ssrf|xxe|csrf|auth_bypass|privilege_escalation|supply_chain|dependency_tampering|model_extraction|adversarial_attack|jailbreak|trojan|backdoor|rootkit|ransomware|crypto_mining|botnet|resource_abuse|denial_of_service|information_disclosure|other",
      "threat_level": int (1-5),
      "confidence": float (0-1),
      "title": "brief summary of what the agent detected",
      "description": "detailed explanation including agent's reasoning",
      "recommendation": "specific actionable remediation steps based on this threat",
      "evidence": [
        {"type": "log_line", "content": "exact excerpt from agent output"},
        {"type": "file_path", "content": "file path if mentioned"},
        {"type": "code_snippet", "content": "suspicious code if quoted"},
        {"type": "pattern", "content": "pattern described by agent"}
      ],
      "detection_method": "how the agent identified it (static analysis, behavioral, etc.)",
      "file_path": "file path if mentioned",
      "code_snippet": "suspicious code if quoted"
    }
  ]
}

If NO security concerns were identified by the agent, return:
{"threats": []}

THREAT LEVEL GUIDELINES:
- Level 5: Critical - Agent identified malware, shellcode, reverse shells, active exploitation
- Level 4: High - Agent refused to execute due to clear security concerns
- Level 3: Medium - Agent warned about suspicious patterns but may have proceeded
- Level 2: Low - Agent noted minor security considerations
- Level 1: Secure - Agent mentioned security best practices or suggestions

CONFIDENCE GUIDELINES:
- 0.9-1.0: Agent explicitly stated the threat with specific evidence
- 0.7-0.9: Agent strongly implied threat with clear behavioral indicators
- 0.5-0.7: Agent showed caution or concern without definitive action
- Below 0.5: Do not extract (insufficient evidence)

IMPORTANT:
- Focus on what the AGENT detected or was concerned about, not general security analysis
- Include both explicit statements and behavioral patterns
- Preserve exact quotes from agent logs in evidence
- If uncertain, err on the side of NOT extracting (false negatives OK, false alarms bad)
- Ignore compilation errors, dependency issues, and non-security technical problems`

	fullPrompt := map[string]interface{}{
		"instructions":      instructions,
		"data":              promptData,
		"output_constraint": "Respond with a single valid JSON object only. Do not include Markdown or explanatory text.",
	}

	promptBytes, _ := json.Marshal(fullPrompt)
	return string(promptBytes)
}

// parseExtractionResponse parses the LLM response into insights
func (s *Service) parseExtractionResponse(response string) ([]agentInsight, error) {
	// Clean markdown code blocks if present
	cleaned := strings.TrimSpace(response)
	if strings.HasPrefix(cleaned, "```") {
		cleaned = strings.Trim(cleaned, "`")
		cleaned = strings.TrimPrefix(cleaned, "json")
		cleaned = strings.TrimSpace(cleaned)
	}

	var data struct {
		Threats []struct {
			ThreatType      string                   `json:"threat_type"`
			ThreatLevel     int                      `json:"threat_level"`
			Confidence      float64                  `json:"confidence"`
			Title           string                   `json:"title"`
			Description     string                   `json:"description"`
			Recommendation  string                   `json:"recommendation"`
			Evidence        []map[string]interface{} `json:"evidence"`
			DetectionMethod string                   `json:"detection_method"`
			FilePath        string                   `json:"file_path"`
			CodeSnippet     string                   `json:"code_snippet"`
		} `json:"threats"`
	}

	if err := json.Unmarshal([]byte(cleaned), &data); err != nil {
		s.logger.Warn("failed to parse extraction response", "error", err, "response", cleaned)
		return []agentInsight{}, nil // Return empty instead of error - non-fatal
	}

	insights := make([]agentInsight, len(data.Threats))
	for i, t := range data.Threats {
		insights[i] = agentInsight{
			ThreatType:      t.ThreatType,
			ThreatLevel:     t.ThreatLevel,
			Confidence:      t.Confidence,
			Title:           t.Title,
			Description:     t.Description,
			Recommendation:  t.Recommendation,
			Evidence:        t.Evidence,
			DetectionMethod: t.DetectionMethod,
			FilePath:        t.FilePath,
			CodeSnippet:     t.CodeSnippet,
		}
	}

	return insights, nil
}

// textOrNull converts a string to pgtype.Text, treating empty string as NULL
func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

// numericFromFloat64 converts a float64 to pgtype.Numeric
func numericFromFloat64(f float64) pgtype.Numeric {
	n := pgtype.Numeric{}
	_ = n.Scan(f)
	return n
}

// createThreatNotification creates a notification when threats are detected
func (s *Service) createThreatNotification(ctx context.Context, analysisID, skillID uuid.UUID, insights []agentInsight) error {
	// Count threats by severity
	criticalCount := 0
	highCount := 0
	for _, insight := range insights {
		if insight.ThreatLevel == 5 {
			criticalCount++
		} else if insight.ThreatLevel == 4 {
			highCount++
		}
	}

	// Build notification title and message
	title := "Security threats detected in skill analysis"
	message := fmt.Sprintf("Analysis complete. Found %d critical and %d high severity threats that require attention.", criticalCount, highCount)

	// Build metadata with threat summary
	metadata := map[string]interface{}{
		"critical_count": criticalCount,
		"high_count":     highCount,
		"total_threats":  len(insights),
	}
	metadataJSON, _ := json.Marshal(metadata)

	// Create notification
	_, err := s.queries.CreateSaaSNotification(ctx, sqlc.CreateSaaSNotificationParams{
		UserID:     pgtype.Text{Valid: false}, // Optional - derived from analysis_id
		Type:       "finding_detected",
		Title:      title,
		Message:    message,
		Metadata:   metadataJSON,
		AnalysisID: pgtype.UUID{Bytes: analysisID, Valid: true},
		SkillID:    pgtype.UUID{Bytes: skillID, Valid: true},
	})
	return err
}
