package skillsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type RunnerClient struct {
	baseURL    string
	httpClient *http.Client
}

type RunnerRequest struct {
	SourceType     string `json:"source_type"`
	SourceRef      string `json:"source_ref"`
	ResolvedRef    string `json:"resolved_ref,omitempty"`
	ArtifactPath   string `json:"artifact_path,omitempty"`
	AgentType      string `json:"agent_type"`
	RunnerMode     string `json:"runner_mode"`
	PromptStrategy string `json:"prompt_strategy"`
	PromptInput    string `json:"prompt_input,omitempty"`
}

type RunnerResponse struct {
	RunID      string `json:"run_id"`
	Status     string `json:"status"`
	RootExecID string `json:"root_exec_id"`
	Error      string `json:"error,omitempty"`
}

func NewRunnerClient(baseURL string, timeout time.Duration) *RunnerClient {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &RunnerClient{
		baseURL: trimmed,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *RunnerClient) StartRun(ctx context.Context, req RunnerRequest) (*RunnerResponse, error) {
	if c == nil || c.baseURL == "" {
		return nil, ErrRunnerNotConfigured
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/run", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("runner error %d: %s", resp.StatusCode, string(data))
	}

	var parsed RunnerResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	return &parsed, nil
}
