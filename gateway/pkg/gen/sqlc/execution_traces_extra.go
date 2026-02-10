package sqlc

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

// DeleteExecutionTraceByAnalysisID removes execution trace rows for a rerun analysis.
func (q *Queries) DeleteExecutionTraceByAnalysisID(ctx context.Context, analysisID pgtype.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM execution_traces WHERE analysis_id = $1`, analysisID)
	return err
}
