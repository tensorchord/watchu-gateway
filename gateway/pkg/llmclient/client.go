// Package llmclient provides a shared OpenAI-compatible LLM client for use across
// multiple modules (e.g., promptinjection, threatinsight).
// This client implements the OpenAI Chat Completions API format and can be used
// with any compatible endpoint (OpenAI, Azure OpenAI, local models via vLLM/litellm, etc.).
package llmclient

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

// Client wraps an OpenAI-compatible chat completions endpoint
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient builds a client using the provided base URL and API key
func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	trimmed := strings.TrimRight(baseURL, "/")
	if trimmed == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		baseURL: trimmed,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Complete sends a chat completion request and returns the response text
// It will retry on 502 errors (bad gateway) up to 3 times with exponential backoff
func (c *Client) Complete(ctx context.Context, model, prompt string, temperature float64, maxTokens int) (string, error) {
	if c == nil {
		return "", fmt.Errorf("LLM client not configured")
	}

	payload := chatRequest{
		Model:       model,
		Messages:    []chatMessage{{Role: "user", Content: prompt}},
		Temperature: temperature,
		MaxTokens:   maxTokens,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Retry logic for 502 errors (bad gateway - often temporary)
	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 100ms, 200ms, 400ms
			backoff := time.Duration(100*(1<<(attempt-1))) * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "", ctx.Err()
			}
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
			lastErr = err
			continue
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		// Check for 502 Bad Gateway error
		if resp.StatusCode == 502 {
			lastErr = fmt.Errorf("LLM API error %d: %s", resp.StatusCode, string(data))
			continue // Retry
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("LLM API error %d: %s", resp.StatusCode, string(data))
		}

		var parsed chatResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return "", err
		}
		if len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
			return "", fmt.Errorf("LLM API returned no choices")
		}
		return parsed.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("LLM API failed after %d attempts: %w", maxRetries, lastErr)
}

// Ping verifies the chat API endpoint is reachable
func (c *Client) Ping(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("LLM client not configured")
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
		return fmt.Errorf("LLM API ping failed: %d", resp.StatusCode)
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
