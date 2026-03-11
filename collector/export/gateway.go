package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/internal/tool"
)

const (
	endpointHealth = "/healthz"
	endpointIngest = "/api/v1/ingest"

	pathExec       = "exec_event"
	pathRequest    = "http_request"
	pathResponse   = "http_response"
	pathStdIO      = "mcp_stdio"
	pathPostgres   = "pg_event"
	pathAgentEvent = "agent_event"

	requestInterval    = time.Second
	maxBatchSize       = 1024
	GatewayChannelSize = 4096
)

type BatchRecord struct {
	Events []any `json:"events"`
}

type RawRecord interface {
	ToRecord(ctx context.Context, host string) any
}

type GatewayClient struct {
	Host    string
	baseURL string
	client  *http.Client
}

func GetHostName() string {
	// prefer Kubernetes Downward API
	if podUID := os.Getenv("POD_UID"); podUID != "" {
		return podUID
	}
	if podName := os.Getenv("POD_NAME"); podName != "" {
		ns := os.Getenv("POD_NAMESPACE")
		if ns == "" {
			ns = "default"
		}
		return fmt.Sprintf("%s/%s", ns, podName)
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return fmt.Sprintf("host:%s", host)
	}
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return fmt.Sprintf("unknown-host-%d", time.Now().UnixNano())
}

func gatewayHealthCheck(ctx context.Context, baseURL string) error {
	link, err := url.JoinPath(baseURL, endpointHealth)
	if err != nil {
		return fmt.Errorf("failed to join URL path: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request to the gateway health endpoint: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request to the gateway health endpoint: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close health check response body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway health check failed with status code: %d", resp.StatusCode)
	}
	return nil
}

func NewGatewayClient(ctx context.Context, baseURL string) (*GatewayClient, error) {
	host := GetHostName()
	if len(baseURL) > 0 {
		err := gatewayHealthCheck(ctx, baseURL)
		if err != nil {
			return nil, err
		}
		log.Debug().Str("host", host).Str("boot_time", bootTime.String()).Msg("init gateway client")
	} else {
		log.Info().Msg("gateway URL is empty, will disable pushing events to the gateway")
	}
	client := &http.Client{}
	return &GatewayClient{client: client, Host: host, baseURL: baseURL}, nil
}

func (gc *GatewayClient) SendEvents(ctx context.Context, endpoint string, events []any) {
	if len(gc.baseURL) == 0 {
		return
	}
	payload, err := json.Marshal(BatchRecord{Events: events})
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal events")
		return
	}
	link, err := url.JoinPath(gc.baseURL, endpointIngest, endpoint)
	if err != nil {
		log.Error().Err(err).Msg("failed to join URL path")
		return
	}
	log.Info().Str("url", link).Int("count", len(events)).Int("payload_bytes", len(payload)).Msg("sending events to gateway")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, link, bytes.NewReader(payload))
	if err != nil {
		log.Error().Err(err).Msg("failed to create HTTP request")
		return
	}
	req.Header.Add("Content-Type", "application/json")
	//nolint:bodyclose // closed in ReadCloserToBytes
	resp, err := gc.client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("url", link).Msg("failed to send HTTP request to gateway")
		return
	}
	respMessage, err := tool.ReadCloserToBytes(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("failed to read error response body")
		respMessage = []byte("unknown error")
	}
	if resp.StatusCode != http.StatusAccepted {
		log.Error().Bytes("resp", respMessage).Int("status", resp.StatusCode).Str("endpoint", endpoint).Msg("failed to ingest the events")
	} else {
		log.Info().Int("count", len(events)).Int("status", resp.StatusCode).Bytes("resp", respMessage).Str("endpoint", endpoint).Msg("successfully ingested events")
	}
}

func (gc *GatewayClient) IngestEvents(ctx context.Context, endpoint string, producer func() []any) {
	ticker := time.NewTicker(requestInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events := producer()
			if len(events) > 0 {
				gc.SendEvents(ctx, endpoint, events)
			}
		}
	}
}

func consumeFromChannel[R RawRecord](ctx context.Context, host string, channel <-chan R) func() []any {
	return func() []any {
		events := make([]any, 0, maxBatchSize)
		for len(events) < maxBatchSize {
			select {
			case raw := <-channel:
				record := raw.ToRecord(ctx, host)
				if record != nil {
					events = append(events, record)
				}
			default:
				return events
			}
		}
		return events
	}
}
