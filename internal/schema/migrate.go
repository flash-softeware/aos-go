package schema

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Migration struct {
	Version int
	Name    string
	Up      string
}

func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	applied, err := loadAppliedVersions(ctx, db)
	if err != nil {
		return err
	}

	for _, migration := range Migrations {
		if applied[migration.Version] {
			continue
		}

		if _, err := db.Exec(ctx, migration.Up); err != nil {
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
	var migrationsTableExists bool
	if err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'schema_migrations'
		);
	`).Scan(&migrationsTableExists); err != nil {
		return nil, fmt.Errorf("detect schema_migrations table: %w", err)
	}
	if !migrationsTableExists {
		if err := baselineExistingSchema(ctx, db); err != nil {
			return nil, err
		}
		return map[int]bool{}, nil
	}

	if err := baselineExistingSchema(ctx, db); err != nil {
		return nil, err
	}

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
