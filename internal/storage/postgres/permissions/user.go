package permissions

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type PermissionsRepository struct {
	q db.Querier
}

func NewPermissionsRepository(q db.Querier) *PermissionsRepository {
	return &PermissionsRepository{q: q}
}

func (r *PermissionsRepository) Create(ctx context.Context, permission *entities.Permission) error {
	resourceType := permission.ResourceType
	if resourceType == "" {
		resourceType = "*"
	}
	action := permission.Action
	if action == "" {
		action = "*"
	}
	_, err := r.q.Exec(ctx, insertPermission,
		permission.ID, resourceType, action, permission.Code, permission.Description,
	)
	return db.MapError(err)
}

func (r *PermissionsRepository) GetByCode(ctx context.Context, code string) (*entities.Permission, error) {
	permission := &entities.Permission{}
	err := r.q.QueryRow(ctx, selectPermissionByCode, code).Scan(
		&permission.ID, &permission.Code, &permission.Description, &permission.ResourceType, &permission.Action,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	return permission, nil
}

func (r *PermissionsRepository) List(ctx context.Context) ([]*entities.Permission, error) {
	rows, err := r.q.Query(ctx, listPermissions)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var permissions []*entities.Permission
	for rows.Next() {
		p := &entities.Permission{}
		if err := rows.Scan(&p.ID, &p.Code, &p.Description, &p.ResourceType, &p.Action); err != nil {
			return nil, db.MapError(err)
		}
		permissions = append(permissions, p)
	}
	return permissions, db.MapError(rows.Err())
}
