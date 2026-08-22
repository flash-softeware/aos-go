package roles

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type RolesRepository struct {
	q db.Querier
}

func NewRolesRepository(q db.Querier) *RolesRepository {
	return &RolesRepository{q: q}
}

func (r *RolesRepository) Create(ctx context.Context, role *entities.Role) error {
	_, err := r.q.Exec(ctx, insertRole, role.ID, role.OrganizationID, role.Name, role.Description, role.IsSystem, role.HasAllPermissions)
	return db.MapError(err)
}

func (r *RolesRepository) scanRole(row interface {
	Scan(dest ...any) error
}) (*entities.Role, error) {
	role := &entities.Role{}
	err := row.Scan(
		&role.ID, &role.OrganizationID, &role.Name, &role.Description, &role.IsSystem, &role.HasAllPermissions,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	return role, nil
}

func (r *RolesRepository) GetByID(ctx context.Context, id string) (*entities.Role, error) {
	return r.scanRole(r.q.QueryRow(ctx, selectRoleByID, id))
}

func (r *RolesRepository) GetByName(ctx context.Context, name string) (*entities.Role, error) {
	return r.scanRole(r.q.QueryRow(ctx, selectRoleByName, name))
}

func (r *RolesRepository) GetSystemByName(ctx context.Context, name string) (*entities.Role, error) {
	return r.scanRole(r.q.QueryRow(ctx, selectSystemRoleByName, name))
}

func (r *RolesRepository) GetByNameForOrg(ctx context.Context, orgIAMID, name string) (*entities.Role, error) {
	return r.scanRole(r.q.QueryRow(ctx, selectRoleByNameForOrg, name, orgIAMID))
}

func (r *RolesRepository) List(ctx context.Context) ([]*entities.Role, error) {
	rows, err := r.q.Query(ctx, listRoles)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var roles []*entities.Role
	for rows.Next() {
		role, err := r.scanRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, db.MapError(rows.Err())
}

func (r *RolesRepository) Delete(ctx context.Context, id string) error {
	_, err := r.q.Exec(ctx, deleteRole, id)
	return db.MapError(err)
}

func (r *RolesRepository) GrantPermission(ctx context.Context, roleID, permissionCode string) (*entities.Permission, error) {
	if _, err := r.q.Exec(ctx, grantRolePermission, roleID, permissionCode); err != nil {
		return nil, db.MapError(err)
	}
	return r.getPermissionByCode(ctx, permissionCode)
}

func (r *RolesRepository) RevokePermission(ctx context.Context, roleID, permissionCode string) (*entities.Permission, error) {
	permission, err := r.getPermissionByCode(ctx, permissionCode)
	if err != nil {
		return nil, err
	}
	if _, err := r.q.Exec(ctx, revokeRolePermission, roleID, permissionCode); err != nil {
		return nil, db.MapError(err)
	}
	return permission, nil
}

func (r *RolesRepository) getPermissionByCode(ctx context.Context, code string) (*entities.Permission, error) {
	permission := &entities.Permission{}
	err := r.q.QueryRow(ctx, selectPermissionByCode, code).Scan(
		&permission.ID, &permission.Code, &permission.Description, &permission.ResourceType, &permission.Action,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	return permission, nil
}
