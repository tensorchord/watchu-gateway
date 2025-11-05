package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds runtime configuration derived from environment variables.
type Config struct {
	Address              string
	DatabaseURL          string
	ShutdownTimeout      time.Duration
	AnalysisTickInterval time.Duration
	AnalysisLookback     time.Duration
	AnalysisHorizon      time.Duration
	AnalysisLag          time.Duration
	AnalysisEnabled      bool
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
		Address:              getEnv("GATEWAY_ADDRESS", defaultAddress),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		ShutdownTimeout:      parseDurationEnv("SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		AnalysisTickInterval: parseDurationEnv("ANALYSIS_TICK_INTERVAL", defaultTickInterval),
		AnalysisLookback:     parseDurationEnv("ANALYSIS_HOST_LOOKBACK", defaultLookback),
		AnalysisHorizon:      parseDurationEnv("ANALYSIS_HORIZON", defaultHorizon),
		AnalysisLag:          parseDurationEnv("ANALYSIS_LAG", defaultLag),
		AnalysisEnabled:      parseBoolEnv("ANALYSIS_ENABLED", true),
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

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
