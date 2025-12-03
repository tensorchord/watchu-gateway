package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/phuslu/log"
)

const (
	EndpointHealth = "/healthz"
	EndpointIngest = "/api/v1/ingest"
	PathExec       = "exec_event"
	PathRequest    = "http_request"
	PathResponse   = "http_response"
	PathStdIO      = "mcp_stdio"

	requestInterval = time.Second
	maxBatchSize    = 1024

	GatewayChannelSize = 4096
)

var (
	bootTime = getBootTime()
)

func getBootTime() *time.Time {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		log.Fatal().Err(err).Msg("failed to get sysinfo")
	}
	uptime := time.Duration(info.Uptime) * time.Second
	bt := time.Now().Add(-uptime)
	return &bt
}

func parseElapsedToTimestamp(elapsed uint64) time.Time {
	return bootTime.Add(time.Duration(elapsed) * time.Nanosecond)
}

type RecordExec struct {
	Timestamp time.Time `json:"timestamp"`
	Pid       int32     `json:"pid"`
	PPid      int32     `json:"ppid"`
	ExecId    string    `json:"exec_id"`
	PExecId   string    `json:"p_exec_id"`
	Cwd       string    `json:"cwd"`
	Comm      string    `json:"comm"`
	Args      string    `json:"args"`
	Host      string    `json:"host"`
}

type RecordRequest struct {
	Timestamp     time.Time       `json:"timestamp"`
	Pid           int32           `json:"pid"`
	Tid           int32           `json:"tid"`
	Uid           int32           `json:"uid"`
	Gid           int32           `json:"gid"`
	Comm          string          `json:"comm"`
	Method        string          `json:"method"`
	URL           string          `json:"url"`
	Protocol      string          `json:"protocol"`
	ContentLength int64           `json:"content_length"`
	Headers       json.RawMessage `json:"headers"`
	Body          []byte          `json:"body"`
	Truncated     bool            `json:"truncated"`
	Host          string          `json:"host"`
}

type RecordResponse struct {
	Timestamp     time.Time       `json:"timestamp"`
	Pid           int32           `json:"pid"`
	Tid           int32           `json:"tid"`
	Uid           int32           `json:"uid"`
	Gid           int32           `json:"gid"`
	Comm          string          `json:"comm"`
	StatusCode    int32           `json:"status_code"`
	Protocol      string          `json:"protocol"`
	ContentLength int64           `json:"content_length"`
	Headers       json.RawMessage `json:"headers"`
	Body          []byte          `json:"body"`
	Truncated     bool            `json:"truncated"`
	Host          string          `json:"host"`
}

type MCP struct {
	JsonRPC string          `json:"jsonrpc"`
	CorrID  int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
	Params  json.RawMessage `json:"params"`
	Method  string          `json:"method"`
}

type RecordStdIO struct {
	Timestamp   time.Time       `json:"timestamp"`
	Pid         int32           `json:"pid"`
	Tid         int32           `json:"tid"`
	Uid         int32           `json:"uid"`
	Gid         int32           `json:"gid"`
	Host        string          `json:"host"`
	MessageType string          `json:"message_type"` // "request" or "response"
	JsonRPC     string          `json:"jsonrpc"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params"`
	Result      json.RawMessage `json:"result"`
	Error       json.RawMessage `json:"error"`
	CorrID      string          `json:"corr_id"`
}

type BatchRecord struct {
	Events []any `json:"events"`
}

type RawRecord interface {
	ToRecord(host string) any
}

type RawExec struct {
	Timestamp time.Time
	Pid       uint32
	PPid      uint32
	ExecId    string
	PExecId   string
	Cwd       string
	Comm      string
	Args      string
}

func (raw RawExec) ToRecord(host string) any {
	return RecordExec{
		Timestamp: raw.Timestamp,
		Pid:       int32(raw.Pid),
		PPid:      int32(raw.PPid),
		ExecId:    raw.ExecId,
		PExecId:   raw.PExecId,
		Cwd:       raw.Cwd,
		Comm:      raw.Comm,
		Args:      raw.Args,
		Host:      host,
	}
}

type RawRequest struct {
	ElapsedNs     uint64
	PidTid        uint64
	UidGid        uint64
	Comm          string
	Method        string
	URL           string
	Protocol      string
	ContentLength int64
	Headers       map[string]string
	Body          []byte
	Truncated     bool
}

func (raw RawRequest) ToRecord(host string) any {
	headers, err := json.Marshal(raw.Headers)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal req headers")
		return nil
	}
	return RecordRequest{
		Timestamp:     parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:           int32(raw.PidTid & 0xFFFFFFFF),
		Tid:           int32(raw.PidTid >> 32),
		Uid:           int32(raw.UidGid & 0xFFFFFFFF),
		Gid:           int32(raw.UidGid >> 32),
		Comm:          raw.Comm,
		Method:        raw.Method,
		URL:           raw.URL,
		Protocol:      raw.Protocol,
		ContentLength: raw.ContentLength,
		Headers:       headers,
		Body:          raw.Body,
		Truncated:     raw.Truncated,
		Host:          host,
	}
}

type RawResponse struct {
	ElapsedNs     uint64
	PidTid        uint64
	UidGid        uint64
	Comm          string
	StatusCode    int
	Protocol      string
	ContentLength int64
	Headers       map[string]string
	Body          []byte
	Truncated     bool
}

func (raw RawResponse) ToRecord(host string) any {
	headers, err := json.Marshal(raw.Headers)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal resp headers")
		return nil
	}
	return RecordResponse{
		Timestamp:     parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:           int32(raw.PidTid & 0xFFFFFFFF),
		Tid:           int32(raw.PidTid >> 32),
		Uid:           int32(raw.UidGid & 0xFFFFFFFF),
		Gid:           int32(raw.UidGid >> 32),
		Comm:          raw.Comm,
		StatusCode:    int32(raw.StatusCode),
		Protocol:      raw.Protocol,
		ContentLength: raw.ContentLength,
		Headers:       headers,
		Body:          raw.Body,
		Truncated:     raw.Truncated,
		Host:          host,
	}
}

type RawStdIO struct {
	ElapsedNs uint64
	PidTid    uint64
	UidGid    uint64
	Rw        uint8
	Data      []byte
}

func (raw RawStdIO) ToRecord(host string) any {
	var messageType string
	switch raw.Rw {
	case 4:
		messageType = "request"
	case 2:
		messageType = "response"
	default:
		messageType = "unknown"
		log.Warn().Uint8("rw", raw.Rw).Msg("unknown stdio message type")
	}
	var mcp MCP
	err := json.Unmarshal(raw.Data, &mcp)
	if err != nil {
		log.Error().Err(err).Bytes("data", raw.Data).Msg("failed to unmarshal mcp message")
		return nil
	}

	return RecordStdIO{
		Timestamp:   parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:         int32(raw.PidTid & 0xFFFFFFFF),
		Tid:         int32(raw.PidTid >> 32),
		Uid:         int32(raw.UidGid & 0xFFFFFFFF),
		Gid:         int32(raw.UidGid >> 32),
		Host:        host,
		MessageType: messageType,
		JsonRPC:     mcp.JsonRPC,
		Method:      mcp.Method,
		Params:      mcp.Params,
		Result:      mcp.Result,
		Error:       mcp.Error,
		CorrID:      strconv.Itoa(mcp.CorrID),
	}
}

func GetHostName() string {
	// prefer Kubernetes Downward API
	if podUid := os.Getenv("POD_UID"); podUid != "" {
		return podUid
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
	if uuid, err := uuid.NewV7(); err == nil {
		return uuid.String()
	}
	return fmt.Sprintf("unknown-host-%d", time.Now().UnixNano())
}

func GatewayHealthCheck(ctx context.Context, baseURL string) error {
	link, err := url.JoinPath(baseURL, EndpointHealth)
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
		err := resp.Body.Close()
		if err != nil {
			log.Error().Err(err).Msg("failed to close health check response body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway health check failed with status code: %d", resp.StatusCode)
	}
	return nil
}

type GatewayClient struct {
	host    string
	baseURL string
	client  *http.Client
}

func NewGatewayClient(ctx context.Context, baseURL string) (*GatewayClient, error) {
	host := GetHostName()
	if len(baseURL) > 0 {
		err := GatewayHealthCheck(ctx, baseURL)
		if err != nil {
			return nil, err
		}
		log.Debug().Str("host", host).Str("boot_time", bootTime.String()).Msg("init gateway client")
	} else {
		log.Info().Msg("gateway URL is empty, will disable pushing events to the gateway")
	}
	client := &http.Client{}
	return &GatewayClient{client: client, host: host, baseURL: baseURL}, nil
}

func (gc *GatewayClient) sendEvents(ctx context.Context, endpoint string, events []any) {
	if len(gc.baseURL) == 0 {
		return
	}
	payload, err := json.Marshal(BatchRecord{Events: events})
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal events")
		return
	}
	link, err := url.JoinPath(gc.baseURL, EndpointIngest, endpoint)
	if err != nil {
		log.Error().Err(err).Msg("failed to join URL path")
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, link, bytes.NewReader(payload))
	if err != nil {
		log.Error().Err(err).Msg("failed to create HTTP request")
		return
	}
	req.Header.Add("Content-Type", "application/json")
	//nolint:bodyclose // closed in ReadCloserToBytes
	resp, err := gc.client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to send HTTP request")
		return
	}
	respMessage, err := ReadCloserToBytes(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("failed to read error response body")
		respMessage = []byte("unknown error")
	}
	if resp.StatusCode != http.StatusAccepted {
		log.Error().Bytes("resp", respMessage).Int("status", resp.StatusCode).Str("endpoint", endpoint).Msg("failed to ingest the events")
	} else {
		log.Debug().Int("count", len(events)).Bytes("resp", respMessage).Str("endpoint", endpoint).Msg("successfully ingested events")
	}
}

func (gc *GatewayClient) ingestEvents(ctx context.Context, endpoint string, producer func() []any) {
	ticker := time.NewTicker(requestInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events := producer()
			if len(events) > 0 {
				gc.sendEvents(ctx, endpoint, events)
			}
		}
	}
}

func consumeFromChannel[R RawRecord](host string, channel <-chan R) func() []any {
	return func() []any {
		events := make([]any, 0, maxBatchSize)
		for len(events) < maxBatchSize {
			select {
			case raw := <-channel:
				record := raw.ToRecord(host)
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

func (gc *GatewayClient) IngestExecEvent(ctx context.Context, channel <-chan *RawExec) {
	gc.ingestEvents(ctx, PathExec, consumeFromChannel(gc.host, channel))
}

func (gc *GatewayClient) IngestRequestEvent(ctx context.Context, channel <-chan *RawRequest) {
	gc.ingestEvents(ctx, PathRequest, consumeFromChannel(gc.host, channel))
}

func (gc *GatewayClient) IngestResponseEvent(ctx context.Context, channel <-chan *RawResponse) {
	gc.ingestEvents(ctx, PathResponse, consumeFromChannel(gc.host, channel))
}

func (gc *GatewayClient) IngestStdIOEvent(ctx context.Context, channel <-chan *RawStdIO) {
	gc.ingestEvents(ctx, PathStdIO, consumeFromChannel(gc.host, channel))
}
