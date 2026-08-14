package me

import (
	"encoding/json"
	"net/http"

	dto "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/request"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	meModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/me"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
)

type MeHandler struct {
	me *meModule.Module
}

func NewMeHandler(me *meModule.Module) *MeHandler {
	return &MeHandler{me: me}
}

func (h *MeHandler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	orgs, err := h.me.ListOrganizations(r.Context(), userID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Organizations fetched", orgs, nil)
}

func (h *MeHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	tenantID := identity.TenantIDFromContext(r.Context())
	orgID := identity.OrgIDFromContext(r.Context())
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}
	if orgID == "" {
		response.SendSuccessResponse(w, http.StatusConflict, "Organization selection required", map[string]interface{}{
			"needs_org_selection": true,
		}, nil)
		return
	}

	codes, err := h.me.ListPermissions(r.Context(), userID, orgID, tenantID)
	if err != nil {
		if err.Error() == "not a member of this organization" {
			response.SendErrorResponse(w, errors.ErrForbidden)
			return
		}
		response.SendErrorResponse(w, err)
		return
	}

	org, _ := h.me.GetOrganization(r.Context(), userID, orgID)
	resp := map[string]interface{}{
		"organization_id": orgID,
		"permissions":     codes,
		"is_org_admin":    isOrgAdminCodes(codes),
	}
	if org != nil {
		resp["role_id"] = org.RoleID
		resp["role_name"] = org.RoleName
	}
	response.SendSuccessResponse(w, http.StatusOK, "Permissions fetched", resp, nil)
}

func isOrgAdminCodes(perms []string) bool {
	for _, p := range perms {
		if p == "*" || p == "organization.*" || p == "member.*" {
			return true
		}
	}
	return false
}

func (h *MeHandler) Can(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	tenantID := identity.TenantIDFromContext(r.Context())
	orgID := identity.OrgIDFromContext(r.Context())
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	var req dto.MeCanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	resourceID := orgID
	if resourceID == "" {
		resourceID = tenantID
	}
	if resourceID == "" {
		response.SendSuccessResponse(w, http.StatusConflict, "Organization selection required", map[string]interface{}{
			"needs_org_selection": true,
			"allowed":             false,
		}, nil)
		return
	}

	allowed, err := h.me.Can(r.Context(), userID, resourceID, req.Permission, tenantID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Permission checked", map[string]bool{"allowed": allowed}, nil)
}

func (h *MeHandler) ListOrgMembers(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	tenantID := identity.TenantIDFromContext(r.Context())
	orgID := identity.OrgIDFromContext(r.Context())
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}
	if orgID == "" {
		response.SendSuccessResponse(w, http.StatusConflict, "Organization selection required", map[string]interface{}{
			"needs_org_selection": true,
		}, nil)
		return
	}

	members, err := h.me.ListOrgMembers(r.Context(), userID, orgID, tenantID)
	if err != nil {
		if err.Error() == "forbidden" || err.Error() == "not a member of this organization" {
			response.SendErrorResponse(w, errors.ErrForbidden)
			return
		}
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Members fetched", members, nil)
}
