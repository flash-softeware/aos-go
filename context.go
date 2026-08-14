package aos

import (
	"context"
	"errors"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
)

// UserOrganization is a resource the user belongs to (e.g. merchant org).
type UserOrganization = response.UserOrganization

// OrgMember is a member of an organization resource.
type OrgMember = response.OrgMember

// ContextAPI exposes read helpers for building application portals (replaces /v1/me/*).
type ContextAPI struct{ a *AOS }

func (a *AOS) Context() *ContextAPI { return &ContextAPI{a: a} }

func (c *ContextAPI) ListOrganizations(ctx context.Context, userID string) ([]UserOrganization, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}
	orgs, err := c.a.App.Store.GetUserOrganizations(ctx, userID)
	if err != nil {
		return nil, err
	}
	if orgs == nil {
		return []UserOrganization{}, nil
	}
	return orgs, nil
}

func (c *ContextAPI) ListPermissions(ctx context.Context, userID, resourceID string) ([]string, error) {
	if userID == "" || resourceID == "" {
		return nil, errors.New("userID and resourceID are required")
	}
	ok, err := c.a.App.Store.UserHasOrgMembership(ctx, userID, resourceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("not a member of this resource")
	}
	return c.a.App.Store.GetUserPermissionCodes(ctx, userID, resourceID)
}

func (c *ContextAPI) ListOrgMembers(ctx context.Context, userID, orgID, tenantID string) ([]OrgMember, error) {
	if userID == "" || orgID == "" {
		return nil, errors.New("userID and orgID are required")
	}
	ok, err := c.a.App.Store.UserHasOrgMembership(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("not a member of this organization")
	}

	allowed, err := c.a.Authz().Can(ctx, AuthzInput{
		UserID:     userID,
		ResourceID: orgID,
		Permission: "member.read",
		TenantID:   tenantID,
	})
	if err != nil {
		return nil, err
	}
	if !allowed {
		allowed, err = c.a.Authz().Can(ctx, AuthzInput{
			UserID:     userID,
			ResourceID: orgID,
			Permission: "merchant.read",
			TenantID:   tenantID,
		})
		if err != nil || !allowed {
			return nil, errors.New("forbidden")
		}
	}

	return c.a.App.Store.GetOrgMembers(ctx, orgID)
}
