package db

import (
	"context"
	stdErrors "errors"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is satisfied by *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func MapError(err error) error {
	if err == nil {
		return nil
	}
	if stdErrors.Is(err, pgx.ErrNoRows) {
		return errors.ErrNotFound
	}
	return errors.ErrInternalServerError
}
