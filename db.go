package watchu

import (
	"database/sql"
	"fmt"

	_ "github.com/marcboeker/go-duckdb/v2"
)

type Storage struct {
	db *sql.DB
}

func NewStorage(dsn string) (*Storage, error) {
	db, err := sql.Open("duckdb", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open duckdb: %w", err)
	}
	return &Storage{db: db}, nil
}
