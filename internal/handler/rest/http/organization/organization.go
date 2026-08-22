package organization

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/request"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	authModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/auth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/organization"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
	"github.com/go-chi/chi/v5"
)

type OrganizationHandler struct {
	orgModule  *organization.Module
	authModule *authModule.Module
}

func NewOrganizationHandler(orgModule *organization.Module, authMod *authModule.Module) *OrganizationHandler {
	return &OrganizationHandler{orgModule: orgModule, authModule: authMod}
}

func (h *OrganizationHandler) extractToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); header != "" {
		if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
			return header[7:]
		}
	}
	if cookie, err := r.Cookie("aos_session"); err == nil {
		return cookie.Value
	}
	return ""
}

func (h *OrganizationHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	if req.Name == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	sess := identity.SessionFromRequest(r)
	userID := req.UserID
	if userID == "" {
		userID = sess.UserID
	}
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	token := h.extractToken(r)
	if token == "" {
		if c, err := r.Cookie("aos_session"); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		if header := r.Header.Get("Authorization"); len(header) > 7 && header[:7] == "Bearer " {
			token = header[7:]
		}
	}

	in := organization.CreateInput{Name: req.Name}
	orgID, err := h.orgModule.Create(r.Context(), userID, token, in)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Organization created", map[string]string{"organizationId": orgID}, nil)
}

func (h *OrganizationHandler) Update(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.orgModule.Update(r.Context(), orgID, req.Name); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Organization updated", nil, nil)
}

func (h *OrganizationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	if err := h.orgModule.Delete(r.Context(), orgID); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Organization deleted", nil, nil)
}

func (h *OrganizationHandler) Invite(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	tenantID := identity.SessionFromRequest(r).TenantID

	var payload struct {
		Email  string `json:"email"`
		RoleID string `json:"role_id"`
		RoleIDCamel string `json:"roleId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	roleID := payload.RoleID
	if roleID == "" {
		roleID = payload.RoleIDCamel
	}

	result, err := h.orgModule.Invite(r.Context(), tenantID, orgID, payload.Email, roleID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}

	response.SendSuccessResponse(w, http.StatusOK, "Invitation sent successfully", result, nil)
}

func (h *OrganizationHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	var req struct {
		UserID string `json:"userId"`
		RoleID string `json:"roleId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.orgModule.AddMember(r.Context(), orgID, req.UserID, req.RoleID); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Member added", nil, nil)
}

func (h *OrganizationHandler) Activate(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	if orgID == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	token := h.extractToken(r)
	if token == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	sess := identity.SessionFromRequest(r)
	if sess.UserID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	if err := h.orgModule.Activate(r.Context(), sess.UserID, token, orgID); err != nil {
		response.SendErrorResponse(w, errors.ErrForbidden)
		return
	}

	authSess, err := h.authModule.ValidateSessionFull(r.Context(), token)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}

	response.SendSuccessResponse(w, http.StatusOK, "Organization activated", map[string]interface{}{
		"organization_id":      orgID,
		"active_resource_id":   authSess.ActiveOrganizationID,
		"user_id":              authSess.UserID,
	}, nil)
}

func (h *OrganizationHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "userId")
	if err := h.orgModule.RemoveMember(r.Context(), orgID, userID); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Member removed", nil, nil)
}
