package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
)

type DataSourceCountResponse struct {
	Source string `json:"source"`
	Hits   int64  `json:"hits"`
}

type DataSourceByRootResponse struct {
	RootExecID *string `json:"root_exec_id,omitempty"`
	RootPID    *int64  `json:"root_pid,omitempty"`
	Source     string  `json:"source"`
	Hits       int64   `json:"hits"`
}

type S3BucketTopResponse struct {
	Bucket string `json:"bucket"`
	Hits   int64  `json:"hits"`
}

type S3StatusCountResponse struct {
	StatusCode *int32 `json:"status_code,omitempty"`
	Hits       int64  `json:"hits"`
}

type S3OperationCountResponse struct {
	Operation *string `json:"operation,omitempty"`
	Hits      int64   `json:"hits"`
}

type S3EventResponse struct {
	Host          string     `json:"host"`
	ResponseID    *string    `json:"response_id,omitempty"`
	RequestID     *string    `json:"request_id,omitempty"`
	Timestamp     *time.Time `json:"timestamp,omitempty"`
	PID           *int32     `json:"pid,omitempty"`
	TID           *int32     `json:"tid,omitempty"`
	Comm          *string    `json:"comm,omitempty"`
	Method        *string    `json:"method,omitempty"`
	URL           *string    `json:"url,omitempty"`
	StatusCode    *int32     `json:"status_code,omitempty"`
	Bucket        *string    `json:"bucket,omitempty"`
	BucketRegion  *string    `json:"bucket_region,omitempty"`
	ObjectKey     *string    `json:"object_key,omitempty"`
	RequestBytes  *int64     `json:"request_bytes,omitempty"`
	ResponseBytes *int64     `json:"response_bytes,omitempty"`
	ContainerID   *string    `json:"container_id,omitempty"`
	ExecID        *string    `json:"exec_id,omitempty"`
	RootExecID    *string    `json:"root_exec_id,omitempty"`
	RootPID       *int64     `json:"root_pid,omitempty"`
	Depth         *int32     `json:"depth,omitempty"`
	Operation     *string    `json:"operation,omitempty"`
}

type PostgresQueryTopResponse struct {
	SQLHash string  `json:"sql_hash"`
	Sample  *string `json:"sample,omitempty"`
	Hits    int64   `json:"hits"`
}

type PostgresEventResponse struct {
	Host        string     `json:"host"`
	PgEventID   *string    `json:"pg_event_id,omitempty"`
	Timestamp   *time.Time `json:"timestamp,omitempty"`
	PID         *int32     `json:"pid,omitempty"`
	TID         *int32     `json:"tid,omitempty"`
	UID         *int32     `json:"uid,omitempty"`
	GID         *int32     `json:"gid,omitempty"`
	Comm        *string    `json:"comm,omitempty"`
	MsgType     *string    `json:"msg_type,omitempty"`
	ContainerID *string    `json:"container_id,omitempty"`
	ExecID      *string    `json:"exec_id,omitempty"`
	RootExecID  *string    `json:"root_exec_id,omitempty"`
	RootPID     *int64     `json:"root_pid,omitempty"`
	Depth       *int32     `json:"depth,omitempty"`
	SQLText     *string    `json:"sql_text,omitempty"`
	SQLHash     *string    `json:"sql_hash,omitempty"`
}

type DataSourceSummaryResponse struct {
	Sources  []DataSourceCountResponse `json:"sources"`
	S3       DataSourceS3Summary       `json:"s3"`
	Postgres DataSourcePostgresSummary `json:"postgres"`
}

type DataSourceS3Summary struct {
	BucketsTop  []S3BucketTopResponse      `json:"buckets_top"`
	StatusCodes []S3StatusCountResponse    `json:"status_codes"`
	Operations  []S3OperationCountResponse `json:"operations"`
}

type DataSourcePostgresSummary struct {
	QueriesTop []PostgresQueryTopResponse `json:"queries_top"`
}

func (h analyticsHandlers) getDataSourceSummary(c *gin.Context) {
	host, since, until, _, ok := parseRangeParams(c)
	if !ok {
		return
	}
	top, ok := parseLimitQuery(c, "limit", 10, 1, 100)
	if !ok {
		return
	}

	rootExecID := strings.TrimSpace(c.Query("root_exec_id"))
	var rootExecIDParam pgtype.Text
	if rootExecID != "" {
		rootExecIDParam = pgtype.Text{String: rootExecID, Valid: true}
	}

	distRows, err := h.queries.GetDataSourceDistributionByHostRange(c.Request.Context(), sqlc.GetDataSourceDistributionByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	s3Buckets, err := h.queries.ListS3BucketsTopNByHostRange(c.Request.Context(), sqlc.ListS3BucketsTopNByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Limit:      top,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	s3Status, err := h.queries.ListS3StatusCountsByHostRange(c.Request.Context(), sqlc.ListS3StatusCountsByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Limit:      top,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	pgQueries, err := h.queries.ListPostgresQueriesTopNByHostRange(c.Request.Context(), sqlc.ListPostgresQueriesTopNByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Limit:      top,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	s3Operations, err := h.queries.ListS3OperationCountsByHostRange(c.Request.Context(), sqlc.ListS3OperationCountsByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Limit:      top,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	sources := make([]DataSourceCountResponse, 0, len(distRows))
	for _, row := range distRows {
		sources = append(sources, DataSourceCountResponse{
			Source: row.Source,
			Hits:   row.Hits,
		})
	}

	bucketsTop := make([]S3BucketTopResponse, 0, len(s3Buckets))
	for _, row := range s3Buckets {
		bucketsTop = append(bucketsTop, S3BucketTopResponse{
			Bucket: bucketString(row.Bucket),
			Hits:   row.Hits,
		})
	}

	statusCodes := make([]S3StatusCountResponse, 0, len(s3Status))
	for _, row := range s3Status {
		statusCodes = append(statusCodes, S3StatusCountResponse{
			StatusCode: int32PtrFromInt4(row.StatusCode),
			Hits:       row.Hits,
		})
	}

	queriesTop := make([]PostgresQueryTopResponse, 0, len(pgQueries))
	for _, row := range pgQueries {
		queriesTop = append(queriesTop, PostgresQueryTopResponse{
			SQLHash: row.SqlHash,
			Sample:  stringPtrIfNotEmpty(row.Sample),
			Hits:    row.Hits,
		})
	}

	operations := make([]S3OperationCountResponse, 0, len(s3Operations))
	for _, row := range s3Operations {
		operations = append(operations, S3OperationCountResponse{
			Operation: stringPtrFromText(row.Operation),
			Hits:      row.Hits,
		})
	}

	c.JSON(http.StatusOK, DataSourceSummaryResponse{
		Sources: sources,
		S3: DataSourceS3Summary{
			BucketsTop:  bucketsTop,
			StatusCodes: statusCodes,
			Operations:  operations,
		},
		Postgres: DataSourcePostgresSummary{
			QueriesTop: queriesTop,
		},
	})
}

func (h analyticsHandlers) getDataSourceByRoot(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}

	rows, err := h.queries.ListDataSourceDistributionByRootExecIDRange(c.Request.Context(), sqlc.ListDataSourceDistributionByRootExecIDRangeParams{
		Host:  host,
		Since: pgtype.Timestamptz{Time: since, Valid: true},
		Until: pgtype.Timestamptz{Time: until, Valid: true},
		Limit: limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]DataSourceByRootResponse, 0, len(rows))
	for _, row := range rows {
		var rootPID *int64
		if row.RootPid > 0 {
			val := row.RootPid
			rootPID = &val
		}
		resp = append(resp, DataSourceByRootResponse{
			RootExecID: stringPtrFromText(row.RootExecID),
			RootPID:    rootPID,
			Source:     row.Source,
			Hits:       row.Hits,
		})
	}
	c.JSON(http.StatusOK, resp)
}

func (h analyticsHandlers) getS3Buckets(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}
	rootExecID := strings.TrimSpace(c.Query("root_exec_id"))
	var rootExecIDParam pgtype.Text
	if rootExecID != "" {
		rootExecIDParam = pgtype.Text{String: rootExecID, Valid: true}
	}

	rows, err := h.queries.ListS3BucketsTopNByHostRange(c.Request.Context(), sqlc.ListS3BucketsTopNByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Limit:      limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]S3BucketTopResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, S3BucketTopResponse{Bucket: bucketString(row.Bucket), Hits: row.Hits})
	}
	c.JSON(http.StatusOK, resp)
}

func bucketString(value interface{}) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func (h analyticsHandlers) getS3Operations(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}
	rootExecID := strings.TrimSpace(c.Query("root_exec_id"))
	var rootExecIDParam pgtype.Text
	if rootExecID != "" {
		rootExecIDParam = pgtype.Text{String: rootExecID, Valid: true}
	}

	rows, err := h.queries.ListS3OperationCountsByHostRange(c.Request.Context(), sqlc.ListS3OperationCountsByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Limit:      limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]S3OperationCountResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, S3OperationCountResponse{
			Operation: stringPtrFromText(row.Operation),
			Hits:      row.Hits,
		})
	}
	c.JSON(http.StatusOK, resp)
}

func (h analyticsHandlers) getS3Events(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}
	rootExecID := strings.TrimSpace(c.Query("root_exec_id"))
	bucket := strings.TrimSpace(c.Query("bucket"))
	operation := strings.TrimSpace(c.Query("operation"))

	var rootExecIDParam pgtype.Text
	if rootExecID != "" {
		rootExecIDParam = pgtype.Text{String: rootExecID, Valid: true}
	}
	var bucketParam pgtype.Text
	if bucket != "" {
		bucketParam = pgtype.Text{String: bucket, Valid: true}
	}
	var operationParam pgtype.Text
	if operation != "" {
		operationParam = pgtype.Text{String: operation, Valid: true}
	}

	rows, err := h.queries.ListProcessS3EventsByHostRange(c.Request.Context(), sqlc.ListProcessS3EventsByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Bucket:     bucketParam,
		Operation:  operationParam,
		Limit:      limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]S3EventResponse, 0, len(rows))
	for _, row := range rows {
		// Handle inferred bucket and bucket_region which are interface{} from COALESCE window functions
		var bucket, bucketRegion *string
		if row.Bucket != nil {
			if str, ok := row.Bucket.(string); ok && str != "" {
				bucket = &str
			}
		}
		if row.BucketRegion != nil {
			if str, ok := row.BucketRegion.(string); ok && str != "" {
				bucketRegion = &str
			}
		}

		resp = append(resp, S3EventResponse{
			Host:          row.Host,
			ResponseID:    uuidPtrFromUUID(row.ResponseID),
			RequestID:     uuidPtrFromUUID(row.RequestID),
			Timestamp:     timePtrFromTimestamptz(row.Timestamp),
			PID:           int32PtrFromInt4(row.Pid),
			TID:           int32PtrFromInt4(row.Tid),
			Comm:          stringPtrFromText(row.Comm),
			Method:        stringPtrFromText(row.Method),
			URL:           stringPtrFromText(row.Url),
			StatusCode:    int32PtrFromInt4(row.StatusCode),
			Bucket:        bucket,
			BucketRegion:  bucketRegion,
			ObjectKey:     stringPtrFromText(row.ObjectKey),
			RequestBytes:  int64PtrFromInt8(row.RequestBytes),
			ResponseBytes: int64PtrFromInt8(row.ResponseBytes),
			ContainerID:   stringPtrFromText(row.ContainerID),
			ExecID:        stringPtrFromText(row.ExecID),
			RootExecID:    stringPtrFromText(row.RootExecID),
			RootPID:       int64PtrFromInt8(row.RootPid),
			Depth:         int32PtrFromInt4(row.Depth),
			Operation:     stringPtrFromText(row.Operation),
		})
	}
	c.JSON(http.StatusOK, resp)
}

func (h analyticsHandlers) getPostgresQueries(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}
	rootExecID := strings.TrimSpace(c.Query("root_exec_id"))
	var rootExecIDParam pgtype.Text
	if rootExecID != "" {
		rootExecIDParam = pgtype.Text{String: rootExecID, Valid: true}
	}

	rows, err := h.queries.ListPostgresQueriesTopNByHostRange(c.Request.Context(), sqlc.ListPostgresQueriesTopNByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		Limit:      limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]PostgresQueryTopResponse, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, PostgresQueryTopResponse{
			SQLHash: row.SqlHash,
			Sample:  stringPtrIfNotEmpty(row.Sample),
			Hits:    row.Hits,
		})
	}
	c.JSON(http.StatusOK, resp)
}

func (h analyticsHandlers) getPostgresEvents(c *gin.Context) {
	host, since, until, limit, ok := parseRangeParams(c)
	if !ok {
		return
	}
	rootExecID := strings.TrimSpace(c.Query("root_exec_id"))
	msgType := strings.TrimSpace(c.Query("msg_type"))
	sqlHash := strings.TrimSpace(c.Query("sql_hash"))

	var rootExecIDParam pgtype.Text
	if rootExecID != "" {
		rootExecIDParam = pgtype.Text{String: rootExecID, Valid: true}
	}
	var msgTypeParam pgtype.Text
	if msgType != "" {
		msgTypeParam = pgtype.Text{String: msgType, Valid: true}
	}
	var sqlHashParam pgtype.Text
	if sqlHash != "" {
		sqlHashParam = pgtype.Text{String: sqlHash, Valid: true}
	}

	rows, err := h.queries.ListProcessPGEventsByHostRange(c.Request.Context(), sqlc.ListProcessPGEventsByHostRangeParams{
		Host:       host,
		Since:      pgtype.Timestamptz{Time: since, Valid: true},
		Until:      pgtype.Timestamptz{Time: until, Valid: true},
		RootExecID: rootExecIDParam,
		MsgType:    msgTypeParam,
		SqlHash:    sqlHashParam,
		Limit:      limit,
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}

	resp := make([]PostgresEventResponse, 0, len(rows))
	for _, row := range rows {
		pid := row.Pid
		tid := row.Tid
		uid := row.Uid
		gid := row.Gid
		resp = append(resp, PostgresEventResponse{
			Host:        row.Host,
			PgEventID:   uuidPtrFromUUID(row.PgEventID),
			Timestamp:   timePtrFromTimestamptz(row.Timestamp),
			PID:         &pid,
			TID:         &tid,
			UID:         &uid,
			GID:         &gid,
			Comm:        stringPtrFromText(row.Comm),
			MsgType:     stringPtrFromText(row.MsgType),
			ContainerID: stringPtrFromText(row.ContainerID),
			ExecID:      stringPtrFromText(row.ExecID),
			RootExecID:  stringPtrFromText(row.RootExecID),
			RootPID:     int64PtrFromInt8(row.RootPid),
			Depth:       int32PtrFromInt4(row.Depth),
			SQLText:     stringPtrIfNotEmpty(row.SqlText),
			SQLHash:     stringPtrIfNotEmpty(row.SqlHash),
		})
	}
	c.JSON(http.StatusOK, resp)
}
