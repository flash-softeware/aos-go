package me

import (
	"context"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/iam"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

type Module struct {
	store storage.Storage
	iam   *iam.Engine
}

func New(store storage.Storage, iamEngine *iam.Engine) *Module {
	return &Module{store: store, iam: iamEngine}
}

func (m *Module) ListOrganizations(ctx context.Context, userID string) ([]response.UserOrganization, error) {
	return m.store.Memberships().ListOrganizationsForUser(ctx, userID)
}

func (m *Module) ListPermissions(ctx context.Context, userID, orgID, tenantID string) ([]string, error) {
	_ = tenantID
	ok, err := m.store.Memberships().HasOnResource(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, aoserrors.ErrNotMemberOfOrganization
	}
	return m.store.Authorization().PermissionCodes(ctx, userID, orgID)
}

func (m *Module) Can(ctx context.Context, userID, resourceID, permission, tenantID string) (bool, error) {
	if resourceID == "" {
		return false, aoserrors.ErrResourceIDRequired
	}
	if permission == "" {
		return false, aoserrors.ErrPermissionRequired
	}
	return m.iam.Can(ctx, iam.CanParams{
		UserID:     userID,
		ResourceID: resourceID,
		Permission: permission,
		TenantID:   tenantID,
	})
}

func (m *Module) ListOrgMembers(ctx context.Context, userID, orgID, tenantID string) ([]response.OrgMember, error) {
	ok, err := m.store.Memberships().HasOnResource(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, aoserrors.ErrNotMemberOfOrganization
	}

	allowed, err := m.iam.Can(ctx, iam.CanParams{
		UserID:     userID,
		ResourceID: orgID,
		Permission: "member.read",
		TenantID:   tenantID,
	})
	if err != nil {
		return nil, err
	}
	if !allowed {
		allowed, err = m.iam.Can(ctx, iam.CanParams{
			UserID:     userID,
			ResourceID: orgID,
			Permission: "organization.read",
			TenantID:   tenantID,
		})
		if err != nil || !allowed {
			return nil, aoserrors.ErrForbidden
		}
	}

	return m.store.Memberships().ListMembers(ctx, "ORGANIZATION", orgID)
}

func (m *Module) GetOrganization(ctx context.Context, userID, orgID string) (*response.UserOrganization, error) {
	orgs, err := m.store.Memberships().ListOrganizationsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, o := range orgs {
		if o.ID == orgID {
			return &o, nil
		}
	}
	return nil, aoserrors.ErrOrganizationNotFound
}
