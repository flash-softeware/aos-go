package auth

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
)

func organizationBlock(pc *response.PortalContext) map[string]interface{} {
	if pc == nil {
		return nil
	}
	block := map[string]interface{}{
		"available":       pc.Organizations,
		"needs_selection": pc.NeedsOrgSelection,
	}
	if pc.ActiveOrganization != nil {
		block["active"] = pc.ActiveOrganization
	}
	return block
}

func (h *AuthHandler) enrichAuthPayload(ctx context.Context, userID, sessionToken string) map[string]interface{} {
	payload := map[string]interface{}{
		"session_token": sessionToken,
		"user_id":       userID,
	}
	if !h.authModule.OrganizationsEnabled() {
		return payload
	}

	sess, err := h.authModule.ValidateSessionFull(ctx, sessionToken)
	if err != nil {
		return payload
	}

	pc, err := h.meModule.BuildPortalContext(ctx, userID, sess.ActiveOrganizationID)
	if err != nil || pc == nil {
		return payload
	}

	if block := organizationBlock(pc); block != nil {
		payload["organization"] = block
	}
	if len(pc.Permissions) > 0 {
		payload["permissions"] = pc.Permissions
	}
	if pc.RoleID != "" {
		payload["role_id"] = pc.RoleID
	}
	return payload
}

func (h *AuthHandler) enrichMePayload(ctx context.Context, userID, sessionOrgID string, user *response.User) map[string]interface{} {
	out := map[string]interface{}{
		"user": user,
		"session": map[string]string{
			"user_id": userID,
		},
	}
	if sessionOrgID != "" {
		sessMap := out["session"].(map[string]string)
		sessMap["organization_id"] = sessionOrgID
		sessMap["active_resource_id"] = sessionOrgID
	}

	if !h.authModule.OrganizationsEnabled() {
		return out
	}

	pc, err := h.meModule.BuildPortalContext(ctx, userID, sessionOrgID)
	if err != nil || pc == nil {
		return out
	}

	if block := organizationBlock(pc); block != nil {
		out["organization"] = block
	}
	if len(pc.Permissions) > 0 {
		out["permissions"] = pc.Permissions
	}
	if pc.RoleID != "" {
		sessMap := out["session"].(map[string]string)
		sessMap["role_id"] = pc.RoleID
		out["role_id"] = pc.RoleID
		out["role_name"] = pc.RoleName
	}
	return out
}
