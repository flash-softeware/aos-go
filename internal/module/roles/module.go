package roles

import (
	"context"
	"fmt"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

type Module struct {
	store storage.Repository
}

func New(store storage.Repository) *Module {
	return &Module{store: store}
}

func (m *Module) Create(ctx context.Context, tenantID, name, description string, isSystem bool) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	roleID, err := m.store.InsertSystemRole(ctx, tx, tenantID, name, description, isSystem)
	if err != nil {
		return "", err
	}
	return roleID, tx.Commit(ctx)
}

func (m *Module) Grant(ctx context.Context, roleID, permissionCode string) error {
	permID, err := m.store.GetPermissionIDByCode(ctx, permissionCode)
	if err != nil || permID == "" {
		return fmt.Errorf("permission not found: %s", permissionCode)
	}

	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.InsertRolePerm(ctx, tx, roleID, permID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *Module) GrantByID(ctx context.Context, roleID, permissionID string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.InsertRolePerm(ctx, tx, roleID, permissionID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *Module) RegisterAndGrant(ctx context.Context, tenantID, roleName, roleDesc, permissionCode, permResourceType, permAction, permDesc string) (roleID string, err error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	roleID, err = m.store.InsertSystemRole(ctx, tx, tenantID, roleName, roleDesc, false)
	if err != nil {
		return "", err
	}

	permID, err := m.store.InsertPermission(ctx, tx, permResourceType, permAction, permissionCode, permDesc)
	if err != nil {
		return "", err
	}

	if err := m.store.InsertRolePerm(ctx, tx, roleID, permID); err != nil {
		return "", err
	}

	return roleID, tx.Commit(ctx)
}
