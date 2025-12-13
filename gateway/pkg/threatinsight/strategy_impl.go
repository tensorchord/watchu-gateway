package threatinsight

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/llmclient"
)

// LLMBasedStrategy implements semantic analysis using an LLM
type LLMBasedStrategy struct {
	queries *sqlc.Queries
	client  *llmclient.Client
	model   string
}

// NewLLMBasedStrategy creates a new LLM-based analysis strategy
func NewLLMBasedStrategy(queries *sqlc.Queries, client *llmclient.Client, model string) AnalysisStrategy {
	return &LLMBasedStrategy{
		queries: queries,
		client:  client,
		model:   model,
	}
}

// Analyze performs semantic analysis on telemetry for the given root_exec_id
func (s *LLMBasedStrategy) Analyze(ctx context.Context, rootExecID string) (*AnalysisResult, error) {
	// Fetch events from the database using sqlc
	rootExecIDText := pgtype.Text{String: rootExecID, Valid: true}
	events, err := s.queries.GetEventsByRootExecID(ctx, sqlc.GetEventsByRootExecIDParams{
		RootExecID: rootExecIDText,
		// Keep these invalid to avoid affecting query results; used only for sqlc type inference.
		TidInt:     pgtype.Int4{},
		MethodText: pgtype.Text{},
		UrlText:    pgtype.Text{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	alerts, err := s.queries.GetHeuristicAlertsByRootExecID(ctx, rootExecIDText)
	if err != nil {
		return nil, fmt.Errorf("failed to get heuristic alerts: %w", err)
	}

	if len(events) == 0 {
		return &AnalysisResult{
			ThreatLevel:     1,
			ThreatType:      "none",
			Confidence:      1.0,
			Summary:         "No events found for analysis",
			Details:         fmt.Sprintf("No telemetry data found for root_exec_id: %s", rootExecID),
			Recommendations: []string{"Verify that the root_exec_id is correct"},
			Evidence:        []map[string]interface{}{},
		}, nil
	}

	// Build the analysis prompt
	prompt, err := s.buildPrompt(events, alerts)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	// Query the LLM
	response, err := s.client.Complete(ctx, s.model, prompt, 0.3, 2048)
	if err != nil {
		return nil, fmt.Errorf("LLM query failed: %w", err)
	}

	// Parse the LLM response
	result, err := s.parseResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return result, nil
}

// eventToMap converts a sqlc event row to map[string]interface{}
func eventToMap(e sqlc.GetEventsByRootExecIDRow) map[string]interface{} {
	m := map[string]interface{}{
		"type":      e.EventType,
		"host":      e.Host,
		"timestamp": e.Timestamp.Time,
		"pid":       e.Pid,
		"comm":      e.Comm,
	}
	// Note: sqlc currently generates Tid/Method/Url as non-null primitives for this UNION query.
	// Preserve prior behavior by only adding them when meaningful.
	if e.Tid != 0 {
		m["tid"] = e.Tid
	}
	if e.Method != "" {
		m["method"] = e.Method
	}
	if e.Url != "" {
		m["url"] = e.Url
	}
	if e.StatusCode.Valid {
		m["status_code"] = e.StatusCode.Int32
	}
	if e.Protocol.Valid {
		m["protocol"] = e.Protocol.String
	}
	if e.Ppid.Valid {
		m["ppid"] = e.Ppid.Int32
	}
	if e.Args.Valid {
		m["args"] = e.Args.String
	}
	if e.ExecID.Valid {
		m["exec_id"] = e.ExecID.String
	}
	return m
}

// alertToMap converts a sqlc alert row to map[string]interface{}
func alertToMap(a sqlc.GetHeuristicAlertsByRootExecIDRow) map[string]interface{} {
	m := map[string]interface{}{
		"alert_id":   a.AlertID,
		"alert_type": a.AlertType,
		"host":       a.Host,
	}
	if a.Severity.Valid {
		m["severity"] = a.Severity.String
	}
	if a.Score.Valid {
		m["score"] = a.Score.Float64
	}
	if a.StartTs.Valid {
		m["start_ts"] = a.StartTs.Time
	}
	if a.EndTs.Valid {
		m["end_ts"] = a.EndTs.Time
	}
	if len(a.Details) > 0 {
		m["details"] = string(a.Details)
	}
	if a.Reason.Valid {
		m["reason"] = a.Reason.String
	}
	return m
}

// buildPrompt constructs the analysis prompt from telemetry data
func (s *LLMBasedStrategy) buildPrompt(events []sqlc.GetEventsByRootExecIDRow, alerts []sqlc.GetHeuristicAlertsByRootExecIDRow) (string, error) {
	// Convert to maps for processing
	eventMaps := make([]map[string]interface{}, len(events))
	for i, e := range events {
		eventMaps[i] = eventToMap(e)
	}
	alertMaps := make([]map[string]interface{}, len(alerts))
	for i, a := range alerts {
		alertMaps[i] = alertToMap(a)
	}

	// Summarize telemetry
	summary := s.summarizeEvents(eventMaps)
	alertSummary := s.summarizeAlerts(alertMaps)
	eventSamples := s.sampleEvents(eventMaps, 20)

	// Build the prompt structure
	promptData := map[string]interface{}{
		"telemetry_summary":  summary,
		"heuristic_findings": alertSummary,
		"event_samples":      eventSamples,
	}

	instructions := `You are a senior security analyst reviewing AI agent telemetry captured by an observability pipeline.

DATA PROVIDED:
- telemetry_summary: aggregate counts and execution timespan for the trace.
- heuristic_findings: alert tallies, severity breakdown, and overall risk_score.
- event_samples: chronologically sampled raw events illustrating representative behavior.

TASKS:
1. Assign threat_level on a 1-5 scale (1=benign, 5=critical) using severity trends, risk_score, and event context.
2. Identify the primary threat_type (prompt_injection, reasoning_loop, data_exfiltration, resource_abuse, coordination_failure, none, or other).
3. Provide a confidence value between 0.0 and 1.0 reflecting evidence strength.
4. Summarize key findings in 1-3 sentences referencing concrete signals.
5. Deliver detailed analysis that ties telemetry facts to your conclusions; cite specific alert_id or event details when possible.
6. Recommend prioritized remediation or monitoring actions that address the observed risks.
7. List evidence entries with type/description/severity, noting timestamps or identifiers if available.

FOCUS AREAS:
- Prompt injection symptoms (unexpected system or network activity after LLM calls).
- Reasoning loops or repetitive failures that waste resources.
- Data exfiltration indicators (sensitive reads preceding outbound requests).
- Resource abuse, credential misuse, or suspicious process launches.
- Multi-agent coordination failures or other anomalies impacting safety.

If information is incomplete, state assumptions and highlight follow-up questions.`

	responseFormat := map[string]interface{}{
		"threat_level":    "int (1-5)",
		"threat_type":     "string",
		"confidence":      "float 0-1",
		"summary":         "string",
		"details":         "string",
		"recommendations": "list of string",
		"evidence":        "list of {type, description, severity}",
	}

	fullPrompt := map[string]interface{}{
		"instructions":      instructions,
		"observations":      promptData,
		"response_format":   responseFormat,
		"output_constraint": "Respond with a single valid JSON object only. Do not surround the output with Markdown or explanatory text.",
	}

	promptBytes, err := json.Marshal(fullPrompt)
	if err != nil {
		return "", err
	}

	return string(promptBytes), nil
}

// summarizeEvents generates aggregate statistics from events
func (s *LLMBasedStrategy) summarizeEvents(events []map[string]interface{}) map[string]interface{} {
	var httpRequests, httpResponses, execEvents int
	var timestamps []time.Time

	for _, event := range events {
		eventType, _ := event["type"].(string)
		switch eventType {
		case "http_request":
			httpRequests++
		case "http_response":
			httpResponses++
		case "exec_event":
			execEvents++
		}

		if ts, ok := event["timestamp"].(time.Time); ok {
			timestamps = append(timestamps, ts)
		}
	}

	var durationHours float64
	if len(timestamps) > 0 {
		minTs := timestamps[0]
		maxTs := timestamps[0]
		for _, ts := range timestamps {
			if ts.Before(minTs) {
				minTs = ts
			}
			if ts.After(maxTs) {
				maxTs = ts
			}
		}
		durationHours = maxTs.Sub(minTs).Hours()
	}

	return map[string]interface{}{
		"total_entries":  len(events),
		"llm_requests":   httpRequests,
		"llm_responses":  httpResponses,
		"system_events":  execEvents,
		"timespan_hours": durationHours,
	}
}

// summarizeAlerts generates aggregate statistics from heuristic alerts
func (s *LLMBasedStrategy) summarizeAlerts(alerts []map[string]interface{}) map[string]interface{} {
	if len(alerts) == 0 {
		return map[string]interface{}{
			"total_alerts":    0,
			"severity_counts": map[string]int{},
			"alert_types":     map[string]int{},
			"risk_score":      0,
		}
	}

	severityCounts := make(map[string]int)
	alertTypes := make(map[string]int)
	var riskScore float64

	severityWeights := map[string]float64{
		"high":   4.0,
		"medium": 2.0,
		"low":    1.0,
	}

	for _, alert := range alerts {
		severity, _ := alert["severity"].(string)
		severity = strings.ToLower(severity)
		severityCounts[severity]++

		alertType, _ := alert["alert_type"].(string)
		alertTypes[alertType]++

		// Calculate risk score
		if score, ok := alert["score"].(float64); ok {
			riskScore += score
		} else if weight, ok := severityWeights[severity]; ok {
			riskScore += weight
		} else {
			riskScore += 1.0
		}
	}

	return map[string]interface{}{
		"total_alerts":    len(alerts),
		"severity_counts": severityCounts,
		"alert_types":     alertTypes,
		"risk_score":      riskScore,
	}
}

// sampleEvents returns a representative sample of events
func (s *LLMBasedStrategy) sampleEvents(events []map[string]interface{}, maxItems int) []map[string]interface{} {
	if len(events) == 0 {
		return []map[string]interface{}{}
	}

	if len(events) <= maxItems {
		return s.stripSensitiveFields(events)
	}

	step := len(events) / maxItems
	if step < 1 {
		step = 1
	}

	var samples []map[string]interface{}
	for i := 0; i < len(events) && len(samples) < maxItems; i += step {
		samples = append(samples, events[i])
	}

	return s.stripSensitiveFields(samples)
}

// stripSensitiveFields removes headers and large body content
func (s *LLMBasedStrategy) stripSensitiveFields(events []map[string]interface{}) []map[string]interface{} {
	keysToSkip := map[string]bool{
		"headers":          true,
		"request_headers":  true,
		"response_headers": true,
		"body":             true,
		"request_body":     true,
		"response_body":    true,
	}

	result := make([]map[string]interface{}, len(events))
	for i, event := range events {
		filtered := make(map[string]interface{})
		for key, value := range event {
			if !keysToSkip[key] {
				filtered[key] = value
			}
		}
		result[i] = filtered
	}

	return result
}

// parseResponse parses the LLM's JSON response into an AnalysisResult
func (s *LLMBasedStrategy) parseResponse(text string) (*AnalysisResult, error) {
	// Clean markdown code blocks if present
	cleaned := strings.TrimSpace(text)
	if strings.HasPrefix(cleaned, "```") {
		cleaned = strings.Trim(cleaned, "`")
		cleaned = strings.TrimPrefix(cleaned, "json")
		cleaned = strings.TrimSpace(cleaned)
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(cleaned), &data); err != nil {
		return &AnalysisResult{
			ThreatLevel:     1,
			ThreatType:      "unknown",
			Confidence:      0.0,
			Summary:         "LLM response parse failure",
			Details:         cleaned,
			Recommendations: []string{},
			Evidence:        []map[string]interface{}{},
		}, nil
	}

	result := &AnalysisResult{}

	// Parse threat_level
	if val, ok := data["threat_level"].(float64); ok {
		result.ThreatLevel = int(val)
	} else {
		result.ThreatLevel = 1
	}

	// Parse threat_type
	if val, ok := data["threat_type"].(string); ok {
		result.ThreatType = val
	} else {
		result.ThreatType = "unknown"
	}

	// Parse confidence
	if val, ok := data["confidence"].(float64); ok {
		result.Confidence = val
	} else {
		result.Confidence = 0.0
	}

	// Parse summary
	if val, ok := data["summary"].(string); ok {
		result.Summary = val
	}

	// Parse details
	if val, ok := data["details"].(string); ok {
		result.Details = val
	}

	// Parse recommendations
	if val, ok := data["recommendations"].([]interface{}); ok {
		for _, item := range val {
			if str, ok := item.(string); ok {
				result.Recommendations = append(result.Recommendations, str)
			}
		}
	}

	// Parse evidence
	if val, ok := data["evidence"].([]interface{}); ok {
		for _, item := range val {
			if evidenceMap, ok := item.(map[string]interface{}); ok {
				result.Evidence = append(result.Evidence, evidenceMap)
			}
		}
	}

	if result.Recommendations == nil {
		result.Recommendations = []string{}
	}
	if result.Evidence == nil {
		result.Evidence = []map[string]interface{}{}
	}

	return result, nil
}
