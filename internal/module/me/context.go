package me

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
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
	orgs, err := m.store.Memberships().ListOrganizationsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if orgs == nil {
		orgs = []response.UserOrganization{}
	}

	pc := &response.PortalContext{
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
	pc.ActiveOrganization = active
	perms, err := m.store.Authorization().PermissionCodes(ctx, userID, active.ID)
	if err == nil && perms != nil {
		pc.Permissions = perms
	}
	pc.IsOrgAdmin = isOrgAdmin(pc.Permissions)
	return pc, nil
}
