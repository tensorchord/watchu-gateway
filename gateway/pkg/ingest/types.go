package ingest

import (
	"encoding/json"
	"time"
)

// HTTPRequestEvent represents an inbound HTTP request event.
type HTTPRequestEvent struct {
	Timestamp     time.Time       `json:"timestamp" binding:"required" db:"timestamp"`
	PID           int32           `json:"pid" binding:"required" db:"pid"`
	TID           int32           `json:"tid" binding:"required" db:"tid"`
	UID           int32           `json:"uid" binding:"required" db:"uid"`
	GID           int32           `json:"gid" binding:"required" db:"gid"`
	Comm          string          `json:"comm" binding:"required" db:"comm"`
	Method        string          `json:"method" binding:"required" db:"method"`
	ContentLength *int64          `json:"content_length" db:"content_length"`
	URL           string          `json:"url" binding:"required" db:"url"`
	Protocol      string          `json:"protocol" binding:"required" db:"protocol"`
	Headers       json.RawMessage `json:"headers" db:"headers"`
	Body          []byte          `json:"body" db:"body"`
	Truncated     bool            `json:"truncated" db:"truncated"`
	Host          string          `json:"host" binding:"required" db:"host"`
}

// HTTPResponseEvent represents an inbound HTTP response event.
type HTTPResponseEvent struct {
	Timestamp     time.Time       `json:"timestamp" binding:"required" db:"timestamp"`
	PID           int32           `json:"pid" binding:"required" db:"pid"`
	TID           int32           `json:"tid" binding:"required" db:"tid"`
	UID           int32           `json:"uid" binding:"required" db:"uid"`
	GID           int32           `json:"gid" binding:"required" db:"gid"`
	Comm          string          `json:"comm" binding:"required" db:"comm"`
	StatusCode    int32           `json:"status_code" binding:"required" db:"status_code"`
	ContentLength *int64          `json:"content_length" db:"content_length"`
	Protocol      string          `json:"protocol" binding:"required" db:"protocol"`
	Headers       json.RawMessage `json:"headers" db:"headers"`
	Body          []byte          `json:"body" db:"body"`
	Truncated     bool            `json:"truncated" db:"truncated"`
	Host          string          `json:"host" binding:"required" db:"host"`
}

// ExecEvent represents a process execution event.
type ExecEvent struct {
	Timestamp time.Time `json:"timestamp" binding:"required" db:"timestamp"`
	PID       int32     `json:"pid" binding:"required" db:"pid"`
	PPID      int32     `json:"ppid" binding:"required" db:"ppid"`
	ExecID    string    `json:"exec_id" binding:"required" db:"exec_id"`
	PExecID   string    `json:"p_exec_id" binding:"required" db:"p_exec_id"`
	CWD       string    `json:"cwd" binding:"required" db:"cwd"`
	Comm      string    `json:"comm" binding:"required" db:"comm"`
	Args      string    `json:"args" binding:"required" db:"args"`
	Host      string    `json:"host" binding:"required" db:"host"`
}
