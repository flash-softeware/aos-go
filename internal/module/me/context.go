package me

import (
	"context"

	"github.com/aos/sdk-go/internal/constant/dto/response"
)

func isOrgAdmin(perms []string) bool {
	for _, p := range perms {
		if p == "*" || p == "organization.*" || p == "member.*" {
			return true
		}
	}
	return false
}

// BuildPortalContext reads org/role/permissions from the session token (sessionOrgID), not from client headers.
func (m *Module) BuildPortalContext(ctx context.Context, userID, sessionOrgID string) (*response.PortalContext, error) {
	orgs, err := m.store.GetUserOrganizations(ctx, userID)
	if err != nil {
		return nil, err
	}
	if orgs == nil {
		orgs = []response.UserOrganization{}
	}

	tenantID, _ := m.store.GetUserDefaultTenant(ctx, userID)

	pc := &response.PortalContext{
		TenantID:      tenantID,
		Organizations: orgs,
		Permissions:   []string{},
	}

	if sessionOrgID == "" {
		if len(orgs) > 1 {
			pc.NeedsOrgSelection = true
		}
		return pc, nil
	}

	var active *response.UserOrganization
	for i := range orgs {
		if orgs[i].ID == sessionOrgID {
			active = &orgs[i]
			break
		}
	}
	if active == nil {
		pc.NeedsOrgSelection = len(orgs) > 0
		return pc, nil
	}

	pc.OrgID = active.ID
	pc.RoleID = active.RoleID
	pc.RoleName = active.RoleName
	perms, err := m.store.GetUserPermissionCodes(ctx, userID, active.ID)
	if err == nil && perms != nil {
		pc.Permissions = perms
	}
	pc.IsOrgAdmin = isOrgAdmin(pc.Permissions)
	return pc, nil
}
