package roles

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

type Module struct {
	store       storage.Storage
	orgsEnabled bool
}

func New(store storage.Storage, orgsEnabled bool) *Module {
	return &Module{store: store, orgsEnabled: orgsEnabled}
}

func (m *Module) OrganizationsEnabled() bool {
	return m.orgsEnabled
}

type CreateInput struct {
	Name                   string
	Description            string
	IsSystem               bool
	OrganizationBusinessID string // business org UUID; required when orgs enabled
}

func (m *Module) validateCreateScope(in CreateInput) error {
	if m.orgsEnabled {
		if in.OrganizationBusinessID == "" {
			return errors.ErrOrganizationIDRequired
		}
		if in.IsSystem {
			return errors.ErrSystemRoleCreateForbidden
		}
		return nil
	}
	if in.OrganizationBusinessID != "" {
		return errors.ErrOrganizationScopeNotAllowed
	}
	return nil
}

func (m *Module) Create(ctx context.Context, in CreateInput) (string, error) {
	if in.Name == "" {
		return "", errors.ErrRoleNameRequired
	}
	if err := m.validateCreateScope(in); err != nil {
		return "", err
	}

	role := &entities.Role{
		ID:          uuid.New().String(),
		Name:        in.Name,
		Description: in.Description,
		IsSystem:    in.IsSystem,
	}

	if in.OrganizationBusinessID != "" {
		org, err := m.store.Resources().GetByBusinessID(ctx, "ORGANIZATION", in.OrganizationBusinessID)
		if err != nil {
			return "", err
		}
		role.OrganizationID = org.ID
		if _, err := m.store.Roles().GetByNameForOrg(ctx, org.ID, in.Name); err == nil {
			return "", errors.ErrRoleAlreadyExistsForOrganization
		}
	} else if _, err := m.store.Roles().GetSystemByName(ctx, in.Name); err == nil {
		return "", errors.ErrSystemRoleAlreadyExists
	}

	if err := m.store.Roles().Create(ctx, role); err != nil {
		return "", err
	}
	return role.ID, nil
}

// CreateLegacy preserves the tenant-scoped signature used by older callers.
func (m *Module) CreateLegacy(ctx context.Context, tenantID, name, description string, isSystem bool) (string, error) {
	_ = tenantID
	return m.Create(ctx, CreateInput{
		Name:        name,
		Description: description,
		IsSystem:    isSystem,
	})
}

func (m *Module) Grant(ctx context.Context, roleID, permissionCode string) error {
	_, err := m.store.Roles().GrantPermission(ctx, roleID, permissionCode)
	return err
}

func (m *Module) GrantByID(ctx context.Context, roleID, permissionID string) error {
	perm, err := m.store.Permissions().GetByCode(ctx, permissionID)
	if err != nil {
		return errors.ErrPermissionNotFound
	}
	_, err = m.store.Roles().GrantPermission(ctx, roleID, perm.Code)
	return err
}

func (m *Module) RegisterAndGrant(ctx context.Context, tenantID, roleName, roleDesc, permissionCode, permResourceType, permAction, permDesc, organizationBusinessID string) (roleID string, err error) {
	_ = tenantID

	roleID, err = m.Create(ctx, CreateInput{
		Name:                   roleName,
		Description:            roleDesc,
		OrganizationBusinessID: organizationBusinessID,
	})
	if err != nil {
		return "", err
	}

	permID := uuid.New().String()
	err = m.store.Transaction(ctx, func(tx storage.Storage) error {
		if err := tx.Permissions().Create(ctx, &entities.Permission{
			ID:           permID,
			Code:         permissionCode,
			Description:  permDesc,
			ResourceType: permResourceType,
			Action:       permAction,
		}); err != nil {
			return err
		}
		_, err := tx.Roles().GrantPermission(ctx, roleID, permissionCode)
		return err
	})
	return roleID, err
}
