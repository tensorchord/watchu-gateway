// Package otelrecv provides an OpenTelemetry OTLP receiver for capturing
// telemetry from AI coding tools like Codex CLI, Claude Code, and Gemini CLI.
package otelrecv

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/phuslu/log"
	"google.golang.org/grpc"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/tensorchord/watchu/collector/export"
)

type OTELReceiver struct {
	collogspb.UnimplementedLogsServiceServer

	grpcServer *grpc.Server
	listener   net.Listener
	eventChan  chan *export.RecordAgentEvent
	client     *export.GatewayClient
	host       string
}

func NewOTELReceiver(ctx context.Context, grpcAddr string, client *export.GatewayClient) (*OTELReceiver, error) {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", grpcAddr, err)
	}

	receiver := &OTELReceiver{
		grpcServer: grpc.NewServer(),
		listener:   listener,
		eventChan:  make(chan *export.RecordAgentEvent, export.GatewayChannelSize),
		client:     client,
		host:       export.GetHostName(),
	}

	collogspb.RegisterLogsServiceServer(receiver.grpcServer, receiver)

	return receiver, nil
}

func (r *OTELReceiver) Start(ctx context.Context) {
	log.Info().Str("addr", r.listener.Addr().String()).Msg("starting OTEL receiver")
	go r.client.IngestAgentEvent(ctx, r.eventChan)
	go func() {
		if err := r.grpcServer.Serve(r.listener); err != nil {
			log.Error().Err(err).Msg("OTEL gRPC server error")
		}
	}()

	<-ctx.Done()
	r.grpcServer.GracefulStop()
}

// Export implements the OTLP LogsService Export RPC
func (r *OTELReceiver) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	for _, resourceLogs := range req.GetResourceLogs() {
		resourceAttrs := extractAttributes(resourceLogs.GetResource().GetAttributes())

		for _, scopeLogs := range resourceLogs.GetScopeLogs() {
			for _, logRecord := range scopeLogs.GetLogRecords() {
				event := r.parseLogRecord(logRecord, resourceAttrs)
				if event != nil {
					select {
					case r.eventChan <- event:
					default:
						log.Warn().Msg("OTEL event channel full, dropping event")
					}
				}
			}
		}
	}

	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (r *OTELReceiver) parseLogRecord(record *logspb.LogRecord, _ map[string]string) *export.RecordAgentEvent {
	attrs := extractAttributes(record.GetAttributes())

	eventName, ok := attrs["event.name"]
	if !ok {
		return nil
	}

	tool, eventType := export.ParseEventName(eventName)
	if tool == "" {
		return nil
	}

	timestamp := time.Unix(0, int64(record.GetTimeUnixNano()))

	event := &export.RecordAgentEvent{
		Timestamp: timestamp,
		Tool:      tool,
		EventName: eventName,
		EventType: eventType,
	}

	// Set common fields based on tool
	switch tool {
	case export.ToolCodex:
		event.ConversationID = attrs["conversation.id"]
		event.Model = attrs["model"]
		event.Slug = attrs["slug"]
		event.AppVersion = attrs["app.version"]
	case export.ToolClaudeCode:
		event.SessionID = attrs["session.id"]
		event.Model = attrs["model"]
		event.AppVersion = attrs["app.version"]
	case export.ToolGeminiCLI:
		event.SessionID = attrs["sessionId"]
		event.Model = attrs["model"]
	}

	// Store all attributes as JSON
	if attrsJSON, err := json.Marshal(attrs); err == nil {
		event.Attributes = attrsJSON
	}

	// Parse event-specific fields based on event type
	switch eventType {
	case export.EventTypeUserPrompt:
		event.Prompt = attrs["prompt"]
		event.PromptLength = parseIntAttr(attrs["prompt_length"])

	case export.EventTypeToolResult, export.EventTypeToolCall:
		event.ToolName = coalesce(attrs["tool_name"], attrs["function_name"])
		event.CallID = attrs["call_id"]
		event.Arguments = coalesce(attrs["arguments"], attrs["function_args"])
		event.Output = attrs["output"]
		event.Success = attrs["success"] == "true"
		event.DurationMs = parseIntAttr(attrs["duration_ms"])
		event.Decision = attrs["decision"]
		event.ErrorMsg = attrs["error"]

	case export.EventTypeAPIRequest:
		event.DurationMs = parseIntAttr(attrs["duration_ms"])
		event.StatusCode = parseIntAttr(attrs["status_code"])
		event.CostUSD = parseFloatAttr(attrs["cost_usd"])

	case export.EventTypeAPIResponse:
		event.DurationMs = parseIntAttr(attrs["duration_ms"])
		event.StatusCode = parseIntAttr(attrs["status_code"])
		event.InputTokenCount = parseIntAttr(coalesce(attrs["input_token_count"], attrs["input_tokens"]))
		event.OutputTokenCount = parseIntAttr(coalesce(attrs["output_token_count"], attrs["output_tokens"]))
		event.CachedTokenCount = parseIntAttr(coalesce(attrs["cached_token_count"], attrs["cache_read_tokens"], attrs["cached_content_token_count"]))
		event.CostUSD = parseFloatAttr(attrs["cost_usd"])

	case export.EventTypeAPIError:
		event.ErrorMsg = attrs["error"]
		event.StatusCode = parseIntAttr(attrs["status_code"])
		event.DurationMs = parseIntAttr(attrs["duration_ms"])
	}

	// Handle Codex-specific sse_event with response.completed
	if tool == export.ToolCodex && eventName == "codex.sse_event" && attrs["event.kind"] == "response.completed" {
		event.InputTokenCount = parseIntAttr(attrs["input_token_count"])
		event.OutputTokenCount = parseIntAttr(attrs["output_token_count"])
		event.CachedTokenCount = parseIntAttr(attrs["cached_token_count"])
		event.ReasoningTokenCount = parseIntAttr(attrs["reasoning_token_count"])
	}

	log.Debug().
		Str("tool", tool).
		Str("event", eventName).
		Str("type", eventType).
		Msg("received AI tool OTEL event")

	return event
}

func extractAttributes(attrs []*commonpb.KeyValue) map[string]string {
	result := make(map[string]string, len(attrs))
	for _, kv := range attrs {
		key := kv.GetKey()
		value := kv.GetValue()
		if value == nil {
			continue
		}

		switch v := value.GetValue().(type) {
		case *commonpb.AnyValue_StringValue:
			result[key] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			result[key] = fmt.Sprintf("%d", v.IntValue)
		case *commonpb.AnyValue_DoubleValue:
			result[key] = fmt.Sprintf("%f", v.DoubleValue)
		case *commonpb.AnyValue_BoolValue:
			if v.BoolValue {
				result[key] = "true"
			} else {
				result[key] = "false"
			}
		}
	}
	return result
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseIntAttr(s string) int64 {
	var v int64
	_, _ = fmt.Sscanf(s, "%d", &v)
	return v
}

func parseFloatAttr(s string) float64 {
	var v float64
	_, _ = fmt.Sscanf(s, "%f", &v)
	return v
}

// Close stops the receiver
func (r *OTELReceiver) Close() {
	r.grpcServer.GracefulStop()
	close(r.eventChan)
}
