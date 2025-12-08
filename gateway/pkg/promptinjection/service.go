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
)

// Options controls prompt injection detection behavior.
type Options struct {
	Enabled         bool
	APIBase         string
	APIKey          string
	Model           string
	Mode            string
	Timeout         time.Duration
	BatchSize       int
	MaxRetries      int
	SampleRate      float64
	MaxQPS          float64
	MaxPromptLength int
	StripToolCalls  bool
}

// Service pulls pending prompts, scores them via an OpenAI-compatible API, and stores the verdict.
type Service struct {
	queries *sqlc.Queries
	client  *Client
	opts    Options
	limiter *rate.Limiter
	logger  *slog.Logger
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

	var client *Client
	if normalized.Enabled {
		client = NewClient(normalized.APIBase, normalized.APIKey, normalized.Timeout)
		if client == nil {
			logger.Warn("prompt injection disabled due to invalid API base", slog.String("base", normalized.APIBase))
			normalized.Enabled = false
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
		queries: queries,
		client:  client,
		opts:    normalized,
		limiter: limiter,
		logger:  logger,
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
	if opts.MaxPromptLength <= 0 {
		opts.MaxPromptLength = 8192
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
		opts.Model = "gpt-4o-mini"
	}
	return opts
}

// Enabled reports whether the detector can be executed.
func (s *Service) Enabled() bool {
	return s != nil && s.opts.Enabled && s.client != nil && s.queries != nil
}

// Ready reports whether downstream dependencies (like the LLM endpoint) are reachable.
func (s *Service) Ready(ctx context.Context) error {
	if s == nil || !s.Enabled() {
		return nil
	}
	return s.client.Ping(ctx)
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

	promptText, truncated, promptSource := extractPromptText(row.Prompt, textFromPg(row.RawRequest), s.opts.MaxPromptLength, s.opts.StripToolCalls)
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

	detectionPrompt := s.renderDetectionPrompt(promptText)
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	recordRequest(row.Host)
	start := time.Now()
	completion, err := s.client.Detect(ctx, s.opts.Model, detectionPrompt)
	observeLatency(row.Host, time.Since(start))
	if err != nil {
		recordFailure(row.Host)
		return s.recordError(ctx, row, err)
	}

	parsed := ParseGuardrailOutput(completion)
	outcome := deriveOutcome(parsed)
	outcome.RawResponse = completion
	outcome.Prompt = promptText
	outcome.PromptTruncated = truncated
	outcome.PromptSource = promptSource

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

func (s *Service) renderDetectionPrompt(promptText string) string {
	trimmed := strings.TrimSpace(promptText)
	if trimmed == "" {
		trimmed = "<unavailable prompt>"
	}
	if s.opts.Mode == "model_based" {
		return trimmed
	}
	return RenderDetectionPrompt(trimmed)
}

type detectionOutcome struct {
	Severity        string
	Categories      []string
	Score           float64
	Reason          string
	RawResponse     string
	Prompt          string
	PromptTruncated bool
	PromptSource    string
	Sampled         bool
}

func deriveOutcome(parsed GuardrailResult) detectionOutcome {
	score := parsed.Score
	if score <= 0 {
		switch strings.ToLower(parsed.Safety) {
		case "unsafe":
			score = 0.9
		case "controversial":
			score = 0.5
		default:
			score = 0.1
		}
	}
	if score > 1 {
		score = 1
	}
	severity := "low"
	switch {
	case score >= 0.7:
		severity = "high"
	case score >= 0.4:
		severity = "medium"
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
		"categories":       outcome.Categories,
		"raw_response":     outcome.RawResponse,
		"prompt_truncated": outcome.PromptTruncated,
		"prompt_source":    outcome.PromptSource,
		"prompt_preview":   preview(outcome.Prompt, 512),
		"sampled":          outcome.Sampled,
		"provider":         textFromPg(row.Provider),
		"observed_at":      timeFromPg(row.ObservedAt),
	}
	rawReq := textFromPg(row.RawRequest)
	if rawReq != "" {
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
