package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime configuration derived from environment variables.
type Config struct {
	Address                     string
	DatabaseURL                 string
	ShutdownTimeout             time.Duration
	AnalysisTickInterval        time.Duration
	AnalysisLookback            time.Duration
	AnalysisHorizon             time.Duration
	AnalysisLag                 time.Duration
	AnalysisEnabled             bool
	PromptInjectionEnabled      bool
	PromptInjectionAPIBase      string
	PromptInjectionAPIKey       string
	PromptInjectionModel        string
	PromptInjectionMode         string
	PromptInjectionTimeout      time.Duration
	PromptInjectionBatchSize    int
	PromptInjectionMaxRetries   int
	PromptInjectionSampleRate   float64
	PromptInjectionMaxQPS       float64
	PromptInjectionMaxPromptLen int
	PromptInjectionStripTools   bool
}

const (
	defaultAddress         = ":8080"
	defaultShutdownTimeout = 15 * time.Second
	defaultTickInterval    = 30 * time.Second
	defaultLookback        = time.Minute
	defaultHorizon         = time.Minute
	defaultLag             = time.Second
)

// Load constructs Config from environment with sane defaults.
func Load() (Config, error) {
	cfg := Config{
		Address:                     getEnv("GATEWAY_ADDRESS", defaultAddress),
		DatabaseURL:                 os.Getenv("DATABASE_URL"),
		ShutdownTimeout:             parseDurationEnv("SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		AnalysisTickInterval:        parseDurationEnv("ANALYSIS_TICK_INTERVAL", defaultTickInterval),
		AnalysisLookback:            parseDurationEnv("ANALYSIS_HOST_LOOKBACK", defaultLookback),
		AnalysisHorizon:             parseDurationEnv("ANALYSIS_HORIZON", defaultHorizon),
		AnalysisLag:                 parseDurationEnv("ANALYSIS_LAG", defaultLag),
		AnalysisEnabled:             parseBoolEnv("ANALYSIS_ENABLED", true),
		PromptInjectionEnabled:      parseBoolEnv("PROMPT_INJECTION_ENABLED", true),
		PromptInjectionAPIBase:      getEnv("PROMPT_INJECTION_API_BASE", "https://api.openai.com/v1"),
		PromptInjectionAPIKey:       os.Getenv("PROMPT_INJECTION_API_KEY"),
		PromptInjectionModel:        getEnv("PROMPT_INJECTION_MODEL", "gpt-4o-mini"),
		PromptInjectionMode:         strings.ToLower(getEnv("PROMPT_INJECTION_MODE", "prompt_based")),
		PromptInjectionTimeout:      parseDurationEnv("PROMPT_INJECTION_TIMEOUT", 15*time.Second),
		PromptInjectionBatchSize:    parseIntEnv("PROMPT_INJECTION_BATCH_SIZE", 10),
		PromptInjectionMaxRetries:   parseIntEnv("PROMPT_INJECTION_MAX_RETRIES", 3),
		PromptInjectionSampleRate:   parseFloatEnv("PROMPT_INJECTION_SAMPLE_RATE", 1.0),
		PromptInjectionMaxQPS:       parseFloatEnv("PROMPT_INJECTION_MAX_QPS", 1.0),
		PromptInjectionMaxPromptLen: parseIntEnv("PROMPT_INJECTION_MAX_PROMPT_CHARS", 8192),
		PromptInjectionStripTools:   parseBoolEnv("PROMPT_INJECTION_STRIP_TOOL_CALLS", true),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL must be set")
	}

	return cfg, nil
}

func parseDurationEnv(key string, def time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return def
	}
	return d
}

func parseBoolEnv(key string, def bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return def
	}
	return b
}

func parseIntEnv(key string, def int) int {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return i
}

func parseFloatEnv(key string, def float64) float64 {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return def
	}
	return f
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
