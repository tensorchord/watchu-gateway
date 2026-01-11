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

// GetThreatAnalysis retrieves the latest threat analysis result for a root execution ID from database
func (s *Service) GetThreatAnalysis(ctx context.Context, rootExecID string) (*threatinsight.AnalysisResult, error) {
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

// AnalyzeThreat performs deep threat analysis on a root execution ID
// It first checks if a recent analysis exists in the database (within 24 hours)
// If found, returns the cached result; otherwise, performs new analysis
func (s *Service) AnalyzeThreat(ctx context.Context, rootExecID string) (*threatinsight.AnalysisResult, error) {
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
		return nil, err
	}

	// Save analysis result to database
	if saveErr := threatinsight.SaveAnalysisResult(ctx, s.queries, rootExecID, result); saveErr != nil {
		s.logger.Warn("failed to save threat analysis result", slog.String("root_exec_id", rootExecID), slog.String("error", saveErr.Error()))
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
	for _, insight := range insights {
		id := uuid.New()
		createdJSON, _ := json.Marshal(insight.Evidence)

		// Build parameters for insert
		params := sqlc.InsertAgentThreatReportParams{
			ID:         pgtype.UUID{Bytes: id, Valid: true},
			CreatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
			UpdatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
			Host:       "localhost", // TODO: get actual host
			RootExecID: textOrNull(rootExecID),
			AgentType:  agentType,
			ThreatType: insight.ThreatType,
			ThreatLevel: int32(insight.ThreatLevel),
			Confidence:  insight.Confidence,
			Title:       insight.Title,
			Description: textOrNull(insight.Description),
			Evidence:    createdJSON,
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
	}

	return nil
}

// agentInsight represents a single threat insight extracted from agent logs
type agentInsight struct {
	ThreatType      string
	ThreatLevel     int
	Confidence      float64
	Title           string
	Description     string
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
      "threat_type": "malicious_code|prompt_injection|data_exfiltration|resource_abuse|other",
      "threat_level": int (1-5),
      "confidence": float (0-1),
      "title": "brief summary of what the agent detected",
      "description": "detailed explanation including agent's reasoning",
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
- Level 1: Info - Agent mentioned security best practices or suggestions

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
