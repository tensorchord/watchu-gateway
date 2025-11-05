package httpapi

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func stringPtrFromText(v pgtype.Text) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

func int32PtrFromInt4(v pgtype.Int4) *int32 {
	if !v.Valid {
		return nil
	}
	val := v.Int32
	return &val
}

func int64PtrFromInt8(v pgtype.Int8) *int64 {
	if !v.Valid {
		return nil
	}
	val := v.Int64
	return &val
}

func float64PtrFromFloat8(v pgtype.Float8) *float64 {
	if !v.Valid {
		return nil
	}
	val := v.Float64
	return &val
}

func float64PtrFromNumeric(v pgtype.Numeric) *float64 {
	if !v.Valid {
		return nil
	}
	f, err := v.Float64Value()
	if err != nil || !f.Valid {
		return nil
	}
	val := f.Float64
	return &val
}

func boolPtrFromBool(v pgtype.Bool) *bool {
	if !v.Valid {
		return nil
	}
	val := v.Bool
	return &val
}

func timePtrFromTimestamptz(v pgtype.Timestamptz) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
}

func uuidPtrFromUUID(v pgtype.UUID) *string {
	if !v.Valid {
		return nil
	}
	uid := uuid.UUID(v.Bytes).String()
	return &uid
}

func jsonRaw(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	clone := make([]byte, len(b))
	copy(clone, b)
	return json.RawMessage(clone)
}

func textParam(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: true}
}
