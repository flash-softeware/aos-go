package me

import (
	"context"
	"errors"

	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/module/iam"
	"github.com/aos/sdk-go/internal/storage"
)

type Module struct {
	store storage.Repository
	iam   *iam.Engine
}

func New(store storage.Repository, iamEngine *iam.Engine) *Module {
	return &Module{store: store, iam: iamEngine}
}

func (m *Module) ListOrganizations(ctx context.Context, userID string) ([]response.UserOrganization, error) {
	return m.store.GetUserOrganizations(ctx, userID)
}

func (m *Module) ListPermissions(ctx context.Context, userID, orgID, tenantID string) ([]string, error) {
	ok, err := m.store.UserHasOrgMembership(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("not a member of this organization")
	}
	return m.store.GetUserPermissionCodes(ctx, userID, orgID)
}

func (m *Module) Can(ctx context.Context, userID, resourceID, permission, tenantID string) (bool, error) {
	if resourceID == "" {
		return false, errors.New("resourceId is required")
	}
	if permission == "" {
		return false, errors.New("permission is required")
	}
	return m.iam.Can(ctx, iam.CanParams{
		UserID:     userID,
		ResourceID: resourceID,
		Permission: permission,
		TenantID:   tenantID,
	})
}

func (m *Module) ListOrgMembers(ctx context.Context, userID, orgID, tenantID string) ([]response.OrgMember, error) {
	ok, err := m.store.UserHasOrgMembership(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("not a member of this organization")
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
			return nil, errors.New("forbidden")
		}
	}

	return m.store.GetOrgMembers(ctx, orgID)
}

func (m *Module) GetOrganization(ctx context.Context, userID, orgID string) (*response.UserOrganization, error) {
	orgs, err := m.store.GetUserOrganizations(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, o := range orgs {
		if o.ID == orgID {
			return &o, nil
		}
	}
	return nil, errors.New("organization not found")
}
