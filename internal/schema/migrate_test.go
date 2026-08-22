package schema_test

import (
	"context"
	"os"
	"testing"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/schema"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunMigrationsFreshDatabase(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://postgres:postgres@localhost:5433/aos_idaas"
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("database unavailable: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `
		DROP SCHEMA public CASCADE;
		CREATE SCHEMA public;
		GRANT ALL ON SCHEMA public TO postgres;
		GRANT ALL ON SCHEMA public TO public;
	`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	if err := schema.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != len(schema.Migrations) {
		t.Fatalf("applied migrations = %d, want %d", count, len(schema.Migrations))
	}

	for _, table := range []string{"users", "iam_resources", "oauth_providers", "audit_logs"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			);
		`, table).Scan(&exists); err != nil {
			t.Fatalf("check %s table: %v", table, err)
		}
		if !exists {
			t.Fatalf("%s table missing after migrate", table)
		}
	}

	for _, table := range []string{"tenants", "organizations", "projects"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			);
		`, table).Scan(&exists); err != nil {
			t.Fatalf("check legacy %s table: %v", table, err)
		}
		if exists {
			t.Fatalf("legacy table %s must not exist in canonical schema", table)
		}
	}

	if err := schema.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}
