package promptinjection

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

// Client wraps an OpenAI-compatible chat completions endpoint.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	maxTokens  int
}

// NewClient builds a client using the provided base URL and API key.
func NewClient(baseURL, apiKey string, timeout time.Duration, maxTokens int) *Client {
	trimmed := strings.TrimRight(baseURL, "/")
	if trimmed == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if maxTokens <= 0 {
		maxTokens = 512
	}
	return &Client{
		baseURL: trimmed,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		maxTokens: maxTokens,
	}
}

// Detect sends the rendered prompt to the remote model and returns the textual verdict.
func (c *Client) Detect(ctx context.Context, model, prompt string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("prompt injection client not configured")
	}

	payload := chatRequest{
		Model:       model,
		Messages:    []chatMessage{{Role: "user", Content: prompt}},
		Temperature: 0,
		MaxTokens:   c.maxTokens,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("prompt injection API %d: %s", resp.StatusCode, string(data))
	}

	var parsed chatResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("prompt injection API returned no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}

// Ping verifies the chat API endpoint is reachable.
func (c *Client) Ping(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("prompt injection client not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.baseURL, nil)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("prompt injection API ping failed: %d", resp.StatusCode)
	}
	return nil
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}
