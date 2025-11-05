# Database Tooling

This directory houses the database schema, migrations, and generated query
bindings for the gateway service. Two tools work together here:

- **Atlas** manages DDL migrations.
- **sqlc** generates type-safe Go code from SQL statements.

## Directory Layout

- `migrations/`: Atlas migration files executed against PostgreSQL. The initial
	bootstrap lives in `000001_init.sql`, which now provisions both the ingest
	tables and the analysis result tables defined under `sqlc/schema/analysis.sql`.
- `sqlc/schema/`: Canonical schema files that sqlc (and Atlas) read when
	generating code or computing diffs. Split into `events.sql` (raw ingest
	tables) and `analysis.sql` (materialized results).
- `sqlc/queries/`: Parameterized SQL used by sqlc to generate Go bindings.

## Working With Atlas

Atlas keeps the schema authoritative and produces ordered migration files under
`migrations/`.

1. **Create a migration** after editing the schema files:
	 ```bash
	 atlas migrate diff \
		 --dir "file://db/migrations" \
		 --to "file://db/sqlc/schema" \
		 --dev-url "docker://postgres/18"
	 ```
	 The `--dev-url` can point to any throwaway PostgreSQL instance; adjust to fit
	 your environment.

2. **Apply migrations** to a target database (only after reviewing the diff):
	 ```bash
	 atlas migrate apply \
		 --dir "file://db/migrations" \
		 --url "$DATABASE_URL"
	 ```

3. **Container bootstrap**: the Docker Compose stack mounts `db/migrations`
	 into `/docker-entrypoint-initdb.d`, so a fresh volume automatically runs the
	 latest `*.sql` files. Drop the `pgdata` volume when migrations change
	 (`docker compose down -v`) to trigger a clean reapply.

## Working With sqlc

sqlc reads the schema and query files to generate Go types and helpers under
`internal/gen/sqlc`.

1. Edit or add SQL files inside `db/sqlc/schema` and `db/sqlc/queries`.

2. Regenerate bindings:
	 ```bash
	 sqlc generate
	 ```

3. Re-run `make fmt`/`make lint` afterwards to keep formatting consistent.

sqlc expects the schema to stay in sync with the migrations that Atlas emits,
so always run the Atlas diff before regenerating code.

## Tips

- Use environment variables (`DATABASE_URL`) consistently across Atlas, sqlc,
	and application code.
- When adding new tables, update both the migration and schema files to keep
	Atlas and sqlc aligned.
- For quick local resets during development, `docker compose down -v` removes
	the database volume and replays the migrations on the next `compose-up`.
