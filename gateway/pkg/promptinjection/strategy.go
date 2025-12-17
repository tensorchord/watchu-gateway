package promptinjection

// DetectionStrategy defines the interface for different prompt injection detection strategies
type DetectionStrategy interface {
	// Name returns the strategy name for logging and identification
	Name() string

	// Detect analyzes the given prompt and returns a detection result
	Detect(prompt string) (GuardrailResult, error)

	// ShouldExtractUserPrompt indicates whether this strategy requires user prompt extraction
	ShouldExtractUserPrompt() bool
}

// StrategyRegistry manages multiple detection strategies
type StrategyRegistry struct {
	strategies map[string]DetectionStrategy
	active     string
}

// NewStrategyRegistry creates a new strategy registry
func NewStrategyRegistry() *StrategyRegistry {
	return &StrategyRegistry{
		strategies: make(map[string]DetectionStrategy),
		active:     "",
	}
}

// Register adds a new detection strategy to the registry
func (r *StrategyRegistry) Register(name string, strategy DetectionStrategy) {
	r.strategies[name] = strategy
}

// SetActive sets the active strategy by name
func (r *StrategyRegistry) SetActive(name string) bool {
	if _, exists := r.strategies[name]; exists {
		r.active = name
		return true
	}
	return false
}

// GetActive returns the currently active strategy
func (r *StrategyRegistry) GetActive() DetectionStrategy {
	if r.active == "" {
		return nil
	}
	return r.strategies[r.active]
}

// List returns all registered strategy names
func (r *StrategyRegistry) List() []string {
	names := make([]string, 0, len(r.strategies))
	for name := range r.strategies {
		names = append(names, name)
	}
	return names
}

// DefaultDetectionTemplate is the standard template for LLM-based detection.
//
// IMPORTANT: The model must not invent actions; it must only cite facts present in INPUT_JSON.
const DefaultDetectionTemplate = `You are a security content classifier. Inspect the following INPUT_JSON and return a single valid JSON object only.

INPUT_JSON contains:
- user_input: the extracted end-user request
- observed_evidence: structured observations extracted from the original request (tool calls, arguments, snippets, indicators). Evidence may be incomplete.

TASK:
1) Classify the request as safety: "safe", "controversial", or "unsafe"
2) Provide categories (array of strings) using only the list below
3) Provide score from 0.00 to 1.00 (higher = more dangerous)
4) Provide a detailed reason (3-8 sentences) citing concrete observations
5) Provide evidence entries for UI drill-down (up to 10 items)

VALID CATEGORIES:
- Violent
- Non-violent Illegal Acts
- Sexual Content or Sexual Acts
- Personally Identifiable Information
- Suicide & Self-Harm
- Unethical Acts
- Politically Sensitive Topics
- Copyright Violation
- Jailbreak
- None

CONSTRAINTS (MUST FOLLOW):
- Only use facts present in INPUT_JSON. Do NOT invent tools, SQL, scripts, outputs, or system actions.
- Use phrasing like "Observed in the request..." rather than "I executed..." or "The system ran...".
- Each evidence[i].quote MUST be an exact substring copied from INPUT_JSON (after redaction), not paraphrased.
- If the evidence is insufficient, say what is missing and lower confidence via score.

OUTPUT JSON SCHEMA:
{
  "safety": "safe|controversial|unsafe",
  "categories": ["..."],
  "score": 0.0,
  "reason": "string",
  "evidence": [
    {
      "id": "string",
      "type": "tool_call|snippet|indicator|tool_result|user_intent|other",
      "source": "user_input|raw_request|tool_args|tool_result",
      "severity": "low|medium|high",
      "quote": "string",
      "interpretation": "string"
    }
  ]
}

INPUT_JSON: %s`
