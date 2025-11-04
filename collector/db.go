package watchu

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"syscall"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/phuslu/log"
)

const (
	TableChannelSize = 1024

	initRequestTable = `
CREATE TABLE IF NOT EXISTS http_request (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	timestamp TIMESTAMPTZ NOT NULL,
	pid UINTEGER NOT NULL,
	tid UINTEGER NOT NULL,
	uid UINTEGER NOT NULL,
	gid UINTEGER NOT NULL,
	comm VARCHAR NOT NULL,
	method VARCHAR NOT NULL,
	content_length BIGINT,
	url VARCHAR NOT NULL,
	protocol VARCHAR NOT NULL,
	headers BLOB,
	body BLOB,
	truncated BOOLEAN NOT NULL
);`
	initResponseTable = `
CREATE TABLE IF NOT EXISTS http_response (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	timestamp TIMESTAMPTZ NOT NULL,
	pid UINTEGER NOT NULL,
	tid UINTEGER NOT NULL,
	uid UINTEGER NOT NULL,
	gid UINTEGER NOT NULL,
	comm VARCHAR NOT NULL,
	status_code USMALLINT NOT NULL,
	content_length BIGINT,
	protocol VARCHAR NOT NULL,
	headers BLOB,
	body BLOB,
	truncated BOOLEAN NOT NULL
);`
	initExecTable = `
CREATE TABLE IF NOT EXISTS exec_events (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	timestamp TIMESTAMPTZ NOT NULL,
	pid UINTEGER NOT NULL,
	ppid UINTEGER NOT NULL,
	exec_id VARCHAR NOT NULL,
	p_exec_id VARCHAR NOT NULL,
	cwd VARCHAR NOT NULL,
	comm VARCHAR NOT NULL,
	args VARCHAR NOT NULL
);`
)

type TableExec struct {
	Timestamp time.Time
	Pid       uint32
	PPid      uint32
	ExecId    string
	PExecId   string
	Cwd       string
	Comm      string
	Args      string
}

type TableRequest struct {
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

type TableResponse struct {
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

func BootTime() (*time.Time, error) {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return nil, fmt.Errorf("failed to get sysinfo: %w", err)
	}
	uptime := time.Duration(info.Uptime) * time.Second
	bt := time.Now().Add(-uptime)
	return &bt, nil
}

type Storage struct {
	db       *sql.DB
	bootTime time.Time
}

func NewStorage(dsn string) (*Storage, error) {
	db, err := sql.Open("duckdb", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open duckdb: %w", err)
	}
	for _, initSQL := range []string{initExecTable, initRequestTable, initResponseTable} {
		_, err = db.Exec(initSQL)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize database table: %w with SQL: %s", err, initSQL)
		}
	}
	log.Info().Msg("duckdb is ready")
	bt, err := BootTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get boot time: %w", err)
	}
	return &Storage{db: db, bootTime: *bt}, nil
}

func (s *Storage) Close() {
	err := s.db.Close()
	if err != nil {
		log.Error().Err(err).Msg("failed to close the database")
	}
}

func (s *Storage) parseTimestamp(elapsed uint64) time.Time {
	return s.bootTime.Add(time.Duration(elapsed) * time.Nanosecond)
}

func (s *Storage) InsertExecEvent(ctx context.Context, channel chan *TableExec) {
	for {
		select {
		case <-ctx.Done():
			return
		case exec := <-channel:
			_, err := s.db.ExecContext(ctx, "INSERT INTO exec_events (timestamp, pid, ppid, exec_id, p_exec_id, cwd, comm, args) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
				exec.Timestamp,
				exec.Pid,
				exec.PPid,
				exec.ExecId,
				exec.PExecId,
				exec.Cwd,
				exec.Comm,
				exec.Args,
			)
			if err != nil {
				log.Error().Err(err).Msg("failed to insert exec event")
			}
		}
	}
}

func (s *Storage) InsertHTTPRequest(ctx context.Context, channel chan *TableRequest) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-channel:
			headers, err := json.Marshal(req.Headers)
			if err != nil {
				log.Error().Err(err).Msg("failed to marshal headers")
				continue
			}
			_, err = s.db.ExecContext(ctx, "INSERT INTO http_request (timestamp, pid, tid, uid, gid, comm, method, url, content_length, protocol, headers, body, truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				s.parseTimestamp(req.ElapsedNs),
				req.PidTid&0xFFFFFFFF,
				req.PidTid>>32,
				req.UidGid&0xFFFFFFFF,
				req.UidGid>>32,
				req.Comm,
				req.Method,
				req.URL,
				req.ContentLength,
				req.Protocol,
				headers,
				req.Body,
				req.Truncated,
			)
			if err != nil {
				log.Error().Err(err).Msg("failed to insert http request")
			}
		}
	}
}

func (s *Storage) InsertHTTPResponse(ctx context.Context, channel chan *TableResponse) {
	for {
		select {
		case <-ctx.Done():
			return
		case resp := <-channel:
			headers, err := json.Marshal(resp.Headers)
			if err != nil {
				log.Error().Err(err).Msg("failed to marshal headers")
				continue
			}
			_, err = s.db.ExecContext(ctx, "INSERT INTO http_response (timestamp, pid, tid, uid, gid, comm, status_code, content_length, protocol,  headers, body, truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				s.parseTimestamp(resp.ElapsedNs),
				resp.PidTid&0xFFFFFFFF,
				resp.PidTid>>32,
				resp.UidGid&0xFFFFFFFF,
				resp.UidGid>>32,
				resp.Comm,
				resp.StatusCode,
				resp.ContentLength,
				resp.Protocol,
				headers,
				resp.Body,
				resp.Truncated,
			)
			if err != nil {
				log.Error().Err(err).Msg("failed to insert http response")
			}
		}
	}
}
