package schema

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Migration struct {
	Version int
	Name    string
	Up      string
}

func RunMigrations(ctx context.Context, db *pgxpool.Pool, tenantType string) error {
	if _, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	if err := baselineExistingSchema(ctx, db); err != nil {
		return err
	}

	applied, err := loadAppliedVersions(ctx, db)
	if err != nil {
		return err
	}

	for _, migration := range Migrations {
		if applied[migration.Version] {
			continue
		}

		sql := adaptSQL(migration.Up, tenantType)
		if strings.TrimSpace(sql) == "" {
			if err := recordMigration(ctx, db, migration); err != nil {
				return err
			}
			continue
		}

		if _, err := db.Exec(ctx, sql); err != nil {
			return fmt.Errorf("migration %03d_%s: %w", migration.Version, migration.Name, err)
		}

		if err := recordMigration(ctx, db, migration); err != nil {
			return err
		}
	}

	return nil
}

func baselineExistingSchema(ctx context.Context, db *pgxpool.Pool) error {
	var usersExists bool
	if err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'users'
		);
	`).Scan(&usersExists); err != nil {
		return fmt.Errorf("detect existing schema: %w", err)
	}
	if !usersExists {
		return nil
	}

	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		return fmt.Errorf("count schema_migrations: %w", err)
	}
	if count > 0 {
		return nil
	}

	for _, migration := range Migrations {
		if err := recordMigration(ctx, db, migration); err != nil {
			return err
		}
	}
	return nil
}

func loadAppliedVersions(ctx context.Context, db *pgxpool.Pool) (map[int]bool, error) {
	rows, err := db.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("load schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func recordMigration(ctx context.Context, db *pgxpool.Pool, migration Migration) error {
	_, err := db.Exec(ctx, `
		INSERT INTO schema_migrations (version, name)
		VALUES ($1, $2)
		ON CONFLICT (version) DO NOTHING;
	`, migration.Version, migration.Name)
	if err != nil {
		return fmt.Errorf("record migration %03d_%s: %w", migration.Version, migration.Name, err)
	}
	return nil
}

func adaptSQL(sql, tenantType string) string {
	if tenantType != "single" {
		return sql
	}

	out := sql
	out = strings.ReplaceAll(out, "tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,", "")
	out = strings.ReplaceAll(out, "tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,", "")
	out = strings.ReplaceAll(out, "tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,", "")
	out = strings.ReplaceAll(out, "tenant_id UUID REFERENCES tenants (id) ON DELETE CASCADE,", "")
	return out
}
