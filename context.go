package aos

import (
	"context"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
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
		return nil, aoserrors.ErrUserIDRequired
	}
	orgs, err := c.a.app.Store.Memberships().ListOrganizationsForUser(ctx, userID)
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
		return nil, aoserrors.ErrUserAndResourceIDRequired
	}
	ok, err := c.a.app.Store.Memberships().HasOnResource(ctx, userID, resourceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, aoserrors.ErrNotMemberOfResource
	}
	return c.a.app.Store.Authorization().PermissionCodes(ctx, userID, resourceID)
}

func (c *ContextAPI) ListOrgMembers(ctx context.Context, userID, orgID, tenantID string) ([]OrgMember, error) {
	if userID == "" || orgID == "" {
		return nil, aoserrors.ErrUserAndOrgIDRequired
	}
	ok, err := c.a.app.Store.Memberships().HasOnResource(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, aoserrors.ErrNotMemberOfOrganization
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
		return nil, aoserrors.ErrForbidden
	}

	return c.a.app.Store.Memberships().ListMembers(ctx, "ORGANIZATION", orgID)
}
