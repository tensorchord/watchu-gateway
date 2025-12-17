package promptinjection

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/time/rate"

	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/textencoding"
)

// Options controls prompt injection detection behavior.
type Options struct {
	Enabled           bool
	APIBase           string
	APIKey            string
	Model             string
	Mode              string
	Timeout           time.Duration
	MaxTokens         int
	BatchSize         int
	MaxRetries        int
	SampleRate        float64
	MaxQPS            float64
	MaxPromptLength   int
	StripToolCalls    bool
	ExtractUserPrompt bool // If true, intelligently extract user prompt from agent framework wrappers; if false, use full prompt

	// EvidenceVerbosity controls how much observed evidence (from raw_request) is provided to the detector.
	// Valid values: minimal|standard|full. Default: standard.
	EvidenceVerbosity string
	// EvidenceMaxChars caps per-snippet evidence size (applies to full mode; standard/minimal use smaller caps).
	// Default: 4096.
	EvidenceMaxChars int
}

// Service pulls pending prompts, scores them via an OpenAI-compatible API, and stores the verdict.
type Service struct {
	queries  *sqlc.Queries
	detector Detector // Use Detector interface instead of holding client directly
	opts     Options
	limiter  *rate.Limiter
	logger   *slog.Logger
}

// NewService constructs a detector with the provided dependencies.
func NewService(queries *sqlc.Queries, opts Options, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}

	normalized := normalizeOptions(opts)
	if queries == nil {
		normalized.Enabled = false
	}

	var detector Detector
	if normalized.Enabled {
		client := NewClient(normalized.APIBase, normalized.APIKey, normalized.Timeout, normalized.MaxTokens)
		if client == nil {
			logger.Warn("prompt injection disabled due to invalid API base", slog.String("base", normalized.APIBase))
			normalized.Enabled = false
		} else {
			// Create detector based on mode
			detector = NewDetector(client, normalized.Model, normalized.Mode)
		}
	}

	var limiter *rate.Limiter
	if normalized.Enabled && normalized.MaxQPS > 0 {
		burst := int(math.Ceil(normalized.MaxQPS))
		if burst < 1 {
			burst = 1
		}
		limiter = rate.NewLimiter(rate.Limit(normalized.MaxQPS), burst)
	}

	return &Service{
		queries:  queries,
		detector: detector,
		opts:     normalized,
		limiter:  limiter,
		logger:   logger,
	}
}

func normalizeOptions(opts Options) Options {
	switch strings.ToLower(opts.Mode) {
	case "model_based":
		opts.Mode = "model_based"
	default:
		opts.Mode = "prompt_based"
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 3
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = 512
	}
	if opts.MaxPromptLength <= 0 {
		opts.MaxPromptLength = 8192
	}
	if strings.TrimSpace(opts.EvidenceVerbosity) == "" {
		opts.EvidenceVerbosity = "standard"
	}
	if opts.EvidenceMaxChars <= 0 {
		opts.EvidenceMaxChars = 4096
	}
	if opts.SampleRate < 0 {
		opts.SampleRate = 0
	}
	if opts.SampleRate > 1 {
		opts.SampleRate = 1
	}
	if opts.APIBase == "" {
		opts.APIBase = "https://api.openai.com/v1"
	}
	if _, err := url.Parse(opts.APIBase); err != nil {
		opts.Enabled = false
	}
	if opts.Model == "" {
		opts.Model = "gpt-4o"
	}
	return opts
}

// Enabled reports whether the detector can be executed.
func (s *Service) Enabled() bool {
	return s != nil && s.opts.Enabled && s.detector != nil && s.queries != nil
}

// Ready reports whether downstream dependencies (like the LLM endpoint) are reachable.
func (s *Service) Ready(ctx context.Context) error {
	if s == nil || !s.Enabled() {
		return nil
	}
	if pinger, ok := s.detector.(interface{ Ping(context.Context) error }); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

// Run evaluates prompts for the requested host within the supplied window.
func (s *Service) Run(ctx context.Context, host string, since, until time.Time) error {
	if !s.Enabled() {
		return nil
	}

	params := sqlc.ListPromptInjectionCandidatesParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		MaxRetries: int32(s.opts.MaxRetries),
		Limit:      int32(s.opts.BatchSize),
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := s.queries.ListPromptInjectionCandidates(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := s.processCandidate(ctx, row); err != nil {
				s.logger.Error("prompt injection evaluation failed", slog.String("host", host), slog.String("error", err.Error()))
			}
		}
		if len(rows) < int(params.Limit) {
			return nil
		}
	}
}

func (s *Service) processCandidate(ctx context.Context, row sqlc.ListPromptInjectionCandidatesRow) error {
	if !row.RequestID.Valid {
		return fmt.Errorf("missing request_id")
	}

	rawReq := textFromPg(row.RawRequest)
	promptText, truncated, promptSource := extractPromptText(row.Prompt, rawReq, s.opts.MaxPromptLength, s.opts.StripToolCalls, s.opts.ExtractUserPrompt)
	if promptText == "" {
		promptText = "<unavailable prompt>"
	}

	digest := sha256.Sum256([]byte(promptText))
	promptHash := hex.EncodeToString(digest[:])

	if !s.shouldSample(digest[:]) {
		outcome := detectionOutcome{
			Severity:        "not_evaluated",
			Categories:      []string{"sampled_out"},
			Score:           0,
			RawResponse:     "skipped due to sampling",
			Prompt:          promptText,
			PromptTruncated: truncated,
			PromptSource:    promptSource,
			Sampled:         true,
		}
		return s.persistResult(ctx, row, promptHash, outcome)
	}

	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	recordRequest(row.Host)
	start := time.Now()

	var parsed GuardrailResult
	var guardrailInput string
	var observed ObservedEvidence

	if strings.EqualFold(s.opts.Mode, "prompt_based") {
		observed = buildObservedEvidence(rawReq, s.opts.EvidenceVerbosity, s.opts.EvidenceMaxChars)
		redactedUserInput := capAndRedact(promptText, maxEvidenceChars(s.opts.EvidenceVerbosity, s.opts.EvidenceMaxChars))
		payload := map[string]any{
			"user_input":        redactedUserInput,
			"observed_evidence": observed,
		}
		inputBytes, _ := json.Marshal(payload)
		guardrailInput = string(inputBytes)
	} else {
		guardrailInput = promptText
	}

	// Use Detector interface for detection (single prompt call)
	parsed, err := s.detector.Detect(ctx, guardrailInput)

	observeLatency(row.Host, time.Since(start))
	if err != nil {
		recordFailure(row.Host)
		return s.recordError(ctx, row, err)
	}

	outcome := deriveOutcome(parsed)
	completion := formatGuardrailResult(parsed)
	outcome.RawResponse = completion
	outcome.Prompt = promptText
	outcome.PromptTruncated = truncated
	outcome.PromptSource = promptSource
	outcome.Reason = strings.TrimSpace(parsed.Reason)
	if strings.EqualFold(s.opts.Mode, "prompt_based") {
		outcome.Evidence = validateGuardrailEvidence(parsed.Evidence, guardrailInput)
		outcome.ObservedEvidence = observed
	}

	if err := s.persistResult(ctx, row, promptHash, outcome); err != nil {
		return err
	}
	if err := s.queries.DeletePromptInjectionError(ctx, sqlc.DeletePromptInjectionErrorParams{Host: row.Host, RequestID: row.RequestID}); err != nil {
		s.logger.Warn("prompt injection error cleanup failed", slog.String("host", row.Host), slog.String("error", err.Error()))
	}

	if outcome.Severity == "high" || outcome.Score >= 0.7 {
		if err := s.raiseAlert(ctx, row, promptHash, outcome); err != nil {
			s.logger.Warn("prompt injection alert upsert failed", slog.String("host", row.Host), slog.String("error", err.Error()))
		}
	}
	return nil
}

func (s *Service) recordError(ctx context.Context, row sqlc.ListPromptInjectionCandidatesRow, runErr error) error {
	_, err := s.queries.UpsertPromptInjectionError(ctx, sqlc.UpsertPromptInjectionErrorParams{
		Host:      row.Host,
		RequestID: row.RequestID,
		LastError: textParam(runErr.Error()),
		UpdatedAt: timestamptzNow(),
	})
	return err
}

type detectionOutcome struct {
	Severity         string
	Categories       []string
	Score            float64
	Reason           string
	Evidence         []GuardrailEvidence
	ObservedEvidence ObservedEvidence
	RawResponse      string
	Prompt           string
	PromptTruncated  bool
	PromptSource     string
	Sampled          bool
}

func deriveOutcome(parsed GuardrailResult) detectionOutcome {
	// First check Safety classification (highest priority)
	safety := strings.ToLower(parsed.Safety)

	var score float64
	var severity string

	// Prefer model score when valid; otherwise map from Safety.
	if parsed.Score > 0 && parsed.Score <= 1 {
		score = parsed.Score
	} else {
		switch safety {
		case "unsafe":
			score = 0.9
		case "controversial":
			score = 0.5
		default:
			score = 0.1
		}
	}

	// Prefer Safety for severity if set, otherwise derive from score.
	switch safety {
	case "unsafe":
		severity = "high"
	case "controversial":
		severity = "medium"
	case "safe":
		severity = "low"
	default:
		severity = "low"
		switch {
		case score >= 0.7:
			severity = "high"
		case score >= 0.4:
			severity = "medium"
		}
	}

	return detectionOutcome{
		Severity:   severity,
		Categories: parsed.Categories,
		Score:      score,
		Reason:     parsed.Reason,
	}
}

func (s *Service) persistResult(ctx context.Context, row sqlc.ListPromptInjectionCandidatesRow, promptHash string, outcome detectionOutcome) error {
	metadata := map[string]any{
		"categories":         outcome.Categories,
		"raw_response":       outcome.RawResponse,
		"prompt_truncated":   outcome.PromptTruncated,
		"prompt_source":      outcome.PromptSource,
		"prompt_preview":     preview(outcome.Prompt, 512),
		"evidence":           outcome.Evidence,
		"observed_evidence":  outcome.ObservedEvidence,
		"evidence_verbosity": s.opts.EvidenceVerbosity,
		"evidence_max_chars": s.opts.EvidenceMaxChars,
		"sampled":            outcome.Sampled,
		"provider":           textFromPg(row.Provider),
		"observed_at":        timeFromPg(row.ObservedAt),
	}
	if rawReq := textFromPg(row.RawRequest); rawReq != "" {
		metadata["raw_request_preview"] = preview(rawReq, 512)
	}
	metaBytes, _ := json.Marshal(metadata)

	params := sqlc.UpsertPromptInjectionResultParams{
		Host:          row.Host,
		RequestID:     row.RequestID,
		SeverityLevel: outcome.Severity,
		Categories:    textParam(strings.Join(outcome.Categories, ",")),
		TraceID:       row.TraceID,
		AgentRunID:    row.AgentRunID,
		PromptHash:    textParam(promptHash),
		Score:         floatParam(outcome.Score),
		Model:         textParam(pickModel(row.Model, s.opts.Model)),
		DetectedAt:    timestamptzNow(),
		Metadata:      metaBytes,
		Reason:        textParam(outcome.Reason),
	}
	return s.queries.UpsertPromptInjectionResult(ctx, params)
}

func (s *Service) raiseAlert(ctx context.Context, row sqlc.ListPromptInjectionCandidatesRow, promptHash string, outcome detectionOutcome) error {
	reqID, _ := uuidFromPg(row.RequestID)
	alertID := fmt.Sprintf("prompt_injection:%s:%s", row.Host, reqID.String())
	details := map[string]any{
		"request_id":     reqID.String(),
		"score":          outcome.Score,
		"categories":     outcome.Categories,
		"prompt_hash":    promptHash,
		"trace_id":       uuidString(row.TraceID),
		"agent_run_id":   uuidString(row.AgentRunID),
		"model":          pickModel(row.Model, s.opts.Model),
		"prompt_preview": preview(outcome.Prompt, 256),
		"evidence":       outcome.Evidence,
	}
	detailBytes, _ := json.Marshal(details)

	start := row.ObservedAt
	if !start.Valid {
		start = timestamptzNow()
	}

	params := sqlc.UpsertPromptInjectionAlertParams{
		AlertID:    alertID,
		Host:       row.Host,
		Severity:   textParam(outcome.Severity),
		Score:      floatParam(outcome.Score),
		StartTs:    start,
		EndTs:      timestamptzNow(),
		RootExecID: coalesceText(row.AgentRootExecID, row.RootExecID),
		RootPid:    coalesceInt(row.AgentRootPid, row.RootPid),
		Details:    detailBytes,
		Reason:     textParam(outcome.Reason),
	}
	return s.queries.UpsertPromptInjectionAlert(ctx, params)
}

func (s *Service) shouldSample(hash []byte) bool {
	if s.opts.SampleRate >= 0.9999 {
		return true
	}
	if s.opts.SampleRate <= 0 {
		return false
	}
	if len(hash) < 8 {
		return true
	}
	value := binary.BigEndian.Uint64(hash[:8])
	ratio := float64(value) / float64(math.MaxUint64)
	return ratio <= s.opts.SampleRate
}

func pickModel(model pgtype.Text, fallback string) string {
	if model.Valid && model.String != "" {
		return model.String
	}
	return fallback
}

func preview(text string, max int) string {
	text = textencoding.RepairUTF8Mojibake(text)
	trimmed, _ := truncateString(text, max)
	return trimmed
}

func uuidFromPg(value pgtype.UUID) (uuid.UUID, bool) {
	if !value.Valid {
		return uuid.UUID{}, false
	}
	u, err := uuid.FromBytes(value.Bytes[:])
	if err != nil {
		return uuid.UUID{}, false
	}
	return u, true
}

func uuidString(value pgtype.UUID) string {
	if u, ok := uuidFromPg(value); ok {
		return u.String()
	}
	return ""
}

func textFromPg(value pgtype.Text) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func textParam(val string) pgtype.Text {
	if val == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: val, Valid: true}
}

func floatParam(val float64) pgtype.Float8 {
	return pgtype.Float8{Float64: val, Valid: true}
}

func timeFromPg(value pgtype.Timestamptz) *time.Time {
	if value.Valid {
		t := value.Time
		return &t
	}
	return nil
}

func timestamptzNow() pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
}

func coalesceText(values ...pgtype.Text) pgtype.Text {
	for _, v := range values {
		if v.Valid && v.String != "" {
			return v
		}
	}
	return pgtype.Text{}
}

func coalesceInt(values ...pgtype.Int8) pgtype.Int8 {
	for _, v := range values {
		if v.Valid {
			return v
		}
	}
	return pgtype.Int8{}
}
