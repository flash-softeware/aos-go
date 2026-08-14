package organization

import (
	"encoding/json"
	"net/http"

	dto "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/request"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/organization"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
	"github.com/go-chi/chi/v5"
)

type OrganizationHandler struct {
	orgModule *organization.Module
}

func NewOrganizationHandler(orgModule *organization.Module) *OrganizationHandler {
	return &OrganizationHandler{orgModule: orgModule}
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
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = sess.TenantID
	}
	if tenantID == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	userID := req.UserID
	if userID == "" {
		userID = sess.UserID
	}

	in := organization.CreateInput{Name: req.Name}
	orgID, err := h.orgModule.Create(r.Context(), tenantID, userID, in)
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

func (h *OrganizationHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "userId")
	if err := h.orgModule.RemoveMember(r.Context(), orgID, userID); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Member removed", nil, nil)
}
