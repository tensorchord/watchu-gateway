package httpapi

import "github.com/tensorchord/watchu/gateway/pkg/ingest"

// HealthResponse represents the JSON payload returned by the health check endpoint.
type HealthResponse struct {
	Status string `json:"status"`
}

// HTTPRequestBatch wraps a collection of HTTP request events.
type HTTPRequestBatch struct {
	Events []ingest.HTTPRequestEvent `json:"events"`
}

// HTTPResponseBatch wraps a collection of HTTP response events.
type HTTPResponseBatch struct {
	Events []ingest.HTTPResponseEvent `json:"events"`
}

// ExecEventBatch wraps a collection of exec events.
type ExecEventBatch struct {
	Events []ingest.ExecEvent `json:"events"`
}

// MCPSTDIOBatch wraps STDIO MCP JSON-RPC events.
type MCPSTDIOBatch struct {
	Events []ingest.MCPSTDIOEvent `json:"events"`
}
