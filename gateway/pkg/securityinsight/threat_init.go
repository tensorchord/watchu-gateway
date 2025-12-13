package securityinsight

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/llmclient"
	"github.com/tensorchord/watchu/gateway/pkg/threatinsight"
)

// initThreatInsight initializes the threat insight detector
func initThreatInsight(queries *sqlc.Queries, opts Options, logger *slog.Logger) (threatinsight.Detector, string, error) {
	baseURL := opts.ThreatInsightBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("OPENAI_BASE_URL")
	}
	if baseURL == "" {
		return nil, "", fmt.Errorf("no base URL configured")
	}

	apiKey := opts.ThreatInsightAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}

	model := opts.ThreatInsightModel
	if model == "" {
		model = "gpt-4o"
	}

	timeout := opts.ThreatInsightTimeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	client := llmclient.NewClient(baseURL, apiKey, timeout)
	detector := threatinsight.NewDetector(queries, client, model)

	logger.Info("threat insight detector initialized", slog.String("model", model))

	return detector, model, nil
}
