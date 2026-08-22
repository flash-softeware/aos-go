package authorization

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type Repository struct {
	q db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{q: q}
}

func (r *Repository) Can(ctx context.Context, userID, resourceID, permission string) (bool, error) {
	var allowed bool
	err := r.q.QueryRow(ctx, checkPermission, userID, resourceID, permission).Scan(&allowed)
	return allowed, db.MapError(err)
}

func (r *Repository) PermissionCodes(ctx context.Context, userID, resourceID string) ([]string, error) {
	rows, err := r.q.Query(ctx, permissionCodes, userID, resourceID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, db.MapError(err)
		}
		codes = append(codes, code)
	}
	return codes, db.MapError(rows.Err())
}
