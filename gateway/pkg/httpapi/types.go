package httpapi

import "github.com/tensorchord/watchu/gateway/pkg/ingest"

// ErrorResponse defines the JSON structure returned on error.
type ErrorResponse struct {
	Error string `json:"error"`
}

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
