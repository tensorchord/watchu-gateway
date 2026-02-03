package export

import (
	"context"
	"encoding/json"
	"strconv"
	"syscall"
	"time"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/internal/container"
)

var (
	bootTime          = getBootTime()
	containerResolver = container.NewContainerResolver()
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
	Timestamp   time.Time `json:"timestamp"`
	Pid         int32     `json:"pid"`
	PPid        int32     `json:"ppid"`
	ExecId      string    `json:"exec_id"`
	PExecId     string    `json:"p_exec_id"`
	Cwd         string    `json:"cwd"`
	Comm        string    `json:"comm"`
	Args        string    `json:"args"`
	Host        string    `json:"host"`
	ContainerID string    `json:"container_id"`
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
	ContainerID   string          `json:"container_id"`
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
	ContainerID   string          `json:"container_id"`
}

type MCP struct {
	JSONRPC string          `json:"jsonrpc"`
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
	ContainerID string          `json:"container_id"`
	MessageType string          `json:"message_type"`
	JSONRPC     string          `json:"jsonrpc"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params"`
	Result      json.RawMessage `json:"result"`
	Error       json.RawMessage `json:"error"`
	CorrID      string          `json:"corr_id"`
}

type RecordPostgres struct {
	Timestamp   time.Time `json:"timestamp"`
	Pid         int32     `json:"pid"`
	Tid         int32     `json:"tid"`
	Uid         int32     `json:"uid"`
	Gid         int32     `json:"gid"`
	Host        string    `json:"host"`
	ContainerID string    `json:"container_id"`
	Comm        string    `json:"comm"`
	Data        []byte    `json:"data"`
	MsgType     string    `json:"msg_type"`
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
	Docker    string
}

func (raw *RawExec) ToRecord(_ context.Context, host string) any {
	return RecordExec{
		Timestamp:   raw.Timestamp,
		Pid:         int32(raw.Pid),
		PPid:        int32(raw.PPid),
		ExecId:      raw.ExecId,
		PExecId:     raw.PExecId,
		Cwd:         raw.Cwd,
		Comm:        raw.Comm,
		Args:        raw.Args,
		Host:        host,
		ContainerID: raw.Docker,
	}
}

type RawRequest struct {
	ElapsedNs     uint64
	PidTid        uint64
	UidGid        uint64
	CgroupID      uint64
	Comm          string
	Method        string
	URL           string
	Protocol      string
	ContentLength int64
	Headers       map[string]string
	Body          []byte
	Truncated     bool
}

func (raw *RawRequest) ToRecord(ctx context.Context, host string) any {
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
		ContainerID:   containerResolver.Resolve(ctx, raw.CgroupID),
	}
}

type RawResponse struct {
	ElapsedNs     uint64
	PidTid        uint64
	UidGid        uint64
	CgroupID      uint64
	Comm          string
	StatusCode    int
	Protocol      string
	ContentLength int64
	Headers       map[string]string
	Body          []byte
	Truncated     bool
}

func (raw *RawResponse) ToRecord(ctx context.Context, host string) any {
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
		ContainerID:   containerResolver.Resolve(ctx, raw.CgroupID),
	}
}

type RawStdIO struct {
	ElapsedNs   uint64
	PidTid      uint64
	UidGid      uint64
	CgroupID    uint64
	MessageType string
	Data        []byte
}

func (raw *RawStdIO) ToRecord(ctx context.Context, host string) any {
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
		ContainerID: containerResolver.Resolve(ctx, raw.CgroupID),
		Host:        host,
		MessageType: raw.MessageType,
		JSONRPC:     mcp.JSONRPC,
		Method:      mcp.Method,
		Params:      mcp.Params,
		Result:      mcp.Result,
		Error:       mcp.Error,
		CorrID:      strconv.Itoa(mcp.CorrID),
	}
}

type RawPostgres struct {
	ElapsedNs uint64
	PidTid    uint64
	UidGid    uint64
	CgroupID  uint64
	Comm      string
	MsgType   string
	Data      []byte
}

func (raw *RawPostgres) ToRecord(ctx context.Context, host string) any {
	return RecordPostgres{
		Timestamp:   parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:         int32(raw.PidTid & 0xFFFFFFFF),
		Tid:         int32(raw.PidTid >> 32),
		Uid:         int32(raw.UidGid & 0xFFFFFFFF),
		Gid:         int32(raw.UidGid >> 32),
		Comm:        raw.Comm,
		Data:        raw.Data,
		MsgType:     raw.MsgType,
		Host:        host,
		ContainerID: containerResolver.Resolve(ctx, raw.CgroupID),
	}
}

const (
	ToolCodex      = "codex"
	ToolClaudeCode = "claude_code"
	ToolGeminiCLI  = "gemini_cli"
)

const (
	EventTypeUserPrompt   = "user_prompt"
	EventTypeAPIRequest   = "api_request"
	EventTypeAPIResponse  = "api_response"
	EventTypeAPIError     = "api_error"
	EventTypeToolResult   = "tool_result"
	EventTypeToolCall     = "tool_call"
	EventTypeToolDecision = "tool_decision"
)

type RecordAgentEvent struct {
	Timestamp      time.Time       `json:"timestamp"`
	Tool           string          `json:"tool"`
	EventName      string          `json:"event_name"`
	EventType      string          `json:"event_type"`
	ConversationID string          `json:"conversation_id,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	Model          string          `json:"model,omitempty"`
	Slug           string          `json:"slug,omitempty"`
	AppVersion     string          `json:"app_version,omitempty"`
	Host           string          `json:"host"`
	Attributes     json.RawMessage `json:"attributes"`

	Prompt       string `json:"prompt,omitempty"`
	PromptLength int64  `json:"prompt_length,omitempty"`

	ToolName   string `json:"tool_name,omitempty"`
	CallID     string `json:"call_id,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	Output     string `json:"output,omitempty"`
	Success    bool   `json:"success,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Decision   string `json:"decision,omitempty"`

	StatusCode int64   `json:"status_code,omitempty"`
	CostUSD    float64 `json:"cost_usd,omitempty"`
	ErrorMsg   string  `json:"error,omitempty"`

	InputTokenCount     int64 `json:"input_token_count,omitempty"`
	OutputTokenCount    int64 `json:"output_token_count,omitempty"`
	CachedTokenCount    int64 `json:"cached_token_count,omitempty"`
	ReasoningTokenCount int64 `json:"reasoning_token_count,omitempty"`
}

func (r *RecordAgentEvent) ToRecord(_ context.Context, host string) any {
	r.Host = host
	return *r
}

func ParseEventName(eventName string) (string, string) {
	for _, prefix := range []string{ToolCodex, ToolClaudeCode, ToolGeminiCLI} {
		if len(eventName) > len(prefix)+1 && eventName[:len(prefix)+1] == prefix+"." {
			return prefix, eventName[len(prefix)+1:]
		}
	}
	return "", ""
}
