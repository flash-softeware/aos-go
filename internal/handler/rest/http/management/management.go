package management

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/request"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/management"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
	"github.com/go-chi/chi/v5"
)

type ManagementHandler struct {
	managementModule *management.Module
}

func NewManagementHandler(managementModule *management.Module) *ManagementHandler {
	return &ManagementHandler{managementModule: managementModule}
}

func (h *ManagementHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if req.TenantID == "" {
		req.TenantID = identity.TenantIDFromContext(r.Context())
	}

	roleID, err := h.managementModule.CreateRole(r.Context(), req.TenantID, req.Name, req.Description)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Role created", map[string]string{"roleId": roleID}, nil)
}

// GET endpoints
func (h *ManagementHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	data, err := h.managementModule.GetUsers(r.Context())
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Users fetched", data, nil)
}
func (h *ManagementHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	data, err := h.managementModule.GetRoles(r.Context())
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Roles fetched", data, nil)
}
func (h *ManagementHandler) GetOrganizations(w http.ResponseWriter, r *http.Request) {
	data, err := h.managementModule.GetOrganizations(r.Context())
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Organizations fetched", data, nil)
}
func (h *ManagementHandler) GetPermissions(w http.ResponseWriter, r *http.Request) {
	data, err := h.managementModule.GetPermissions(r.Context())
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Permissions fetched", data, nil)
}
func (h *ManagementHandler) GetMemberships(w http.ResponseWriter, r *http.Request) {
	data, err := h.managementModule.GetMemberships(r.Context())
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Memberships fetched", data, nil)
}
func (h *ManagementHandler) GetTenants(w http.ResponseWriter, r *http.Request) {
	data, err := h.managementModule.GetTenants(r.Context())
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Tenants fetched", data, nil)
}
func (h *ManagementHandler) GetOAuthProviders(w http.ResponseWriter, r *http.Request) {
	tenantID := identity.SessionFromRequest(r).TenantID
	data, err := h.managementModule.GetOAuthProviders(r.Context(), tenantID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "OAuth Providers fetched", data, nil)
}

// Admin Write endpoints
func (h *ManagementHandler) HandleProjects(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	orgID := chi.URLParam(r, "orgId")

	switch r.Method {
	case http.MethodGet:
		data, err := h.managementModule.GetProjects(r.Context(), orgID)
		if err != nil {
			response.SendErrorResponse(w, err)
			return
		}
		response.SendSuccessResponse(w, http.StatusOK, "Projects fetched", data, nil)
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.SendErrorResponse(w, errors.ErrBadRequest)
			return
		}
		projID, err := h.managementModule.CreateProject(r.Context(), orgID, req.Name)
		if err != nil {
			response.SendErrorResponse(w, err)
			return
		}
		response.SendSuccessResponse(w, http.StatusOK, "Project created", map[string]string{"projectId": projID}, nil)
	case http.MethodPut:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.SendErrorResponse(w, errors.ErrBadRequest)
			return
		}
		if err := h.managementModule.UpdateProject(r.Context(), id, req.Name); err != nil {
			response.SendErrorResponse(w, err)
			return
		}
		response.SendSuccessResponse(w, http.StatusOK, "Project updated", nil, nil)
	case http.MethodDelete:
		if err := h.managementModule.DeleteProject(r.Context(), id); err != nil {
			response.SendErrorResponse(w, err)
			return
		}
		response.SendSuccessResponse(w, http.StatusOK, "Project deleted", nil, nil)
	default:
		response.SendErrorResponse(w, errors.ErrBadRequest)
	}
}

func (h *ManagementHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Slug, Type string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	id, err := h.managementModule.CreateTenant(r.Context(), req.Name, req.Slug, req.Type)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Tenant created", map[string]string{"tenantId": id}, nil)
}
func (h *ManagementHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct{ Name, Description string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.managementModule.UpdateRole(r.Context(), id, req.Name, req.Description); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Role updated", nil, nil)
}
func (h *ManagementHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.managementModule.DeleteRole(r.Context(), id); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Role deleted", nil, nil)
}

func (h *ManagementHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ids, err := h.managementModule.GetRolePermissionIDs(r.Context(), id)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Role permissions fetched", ids, nil)
}

func (h *ManagementHandler) UpdateRolePermissions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.managementModule.ReplaceRolePermissions(r.Context(), id, req.PermissionIDs); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Role permissions updated", nil, nil)
}
func (h *ManagementHandler) CreatePermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceType string `json:"resource_type"`
		Action       string `json:"action"`
		Code         string `json:"code"`
		Description  string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	resourceType := strings.ToLower(strings.TrimSpace(req.ResourceType))
	action := strings.ToLower(strings.TrimSpace(req.Action))
	code := strings.TrimSpace(req.Code)
	if code == "" && resourceType != "" && action != "" {
		code = resourceType + "." + action
	}
	description := strings.TrimSpace(req.Description)
	if description == "" && code != "" {
		description = "Permission for " + code
	}
	if resourceType == "" || action == "" || code == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	id, err := h.managementModule.CreatePermission(r.Context(), resourceType, action, code, description)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Permission created", map[string]string{"permissionId": id}, nil)
}
func (h *ManagementHandler) AssignMembership(w http.ResponseWriter, r *http.Request) {
	var req struct{ MembershipID, ResourceID, RoleID string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.managementModule.AssignUserRole(r.Context(), req.MembershipID, req.ResourceID, req.RoleID); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Membership assigned", nil, nil)
}
func (h *ManagementHandler) ConfigureOAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID     string `json:"tenantId"`
		Provider     string `json:"provider"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		ClientIDAlt     string `json:"client_id"`
		ClientSecretAlt string `json:"client_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	clientID := req.ClientID
	if clientID == "" {
		clientID = req.ClientIDAlt
	}
	clientSecret := req.ClientSecret
	if clientSecret == "" {
		clientSecret = req.ClientSecretAlt
	}
	if req.TenantID == "" {
		req.TenantID = identity.SessionFromRequest(r).TenantID
	}
	if req.Provider == "" || clientID == "" || clientSecret == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.managementModule.ConfigureOAuth(r.Context(), req.TenantID, req.Provider, clientID, clientSecret); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "OAuth configured", nil, nil)
}

func (h *ManagementHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	tenantID := identity.SessionFromRequest(r).TenantID
	action := r.URL.Query().Get("action")
	logs, err := h.managementModule.GetAuditLogs(r.Context(), tenantID, action, 50, 0)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Audit logs fetched", map[string]interface{}{
		"total": len(logs),
		"items": logs,
	}, nil)
}

func (h *ManagementHandler) GetApiKeys(w http.ResponseWriter, r *http.Request) {
	tenantID := identity.TenantIDFromContext(r.Context())
	keys, err := h.managementModule.GetApiKeys(r.Context(), tenantID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "API keys fetched", keys, nil)
}

func (h *ManagementHandler) CreateApiKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	sess := identity.SessionFromRequest(r)
	key, err := h.managementModule.CreateApiKey(r.Context(), sess.TenantID, sess.UserID, req.Name, req.Scopes)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "API key created", key, nil)
}

func (h *ManagementHandler) RevokeApiKey(w http.ResponseWriter, r *http.Request) {
	if err := h.managementModule.RevokeApiKey(r.Context(), chi.URLParam(r, "id")); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "API key revoked", map[string]bool{"revoked": true}, nil)
}

func (h *ManagementHandler) GetWebhooks(w http.ResponseWriter, r *http.Request) {
	tenantID := identity.TenantIDFromContext(r.Context())
	hooks, err := h.managementModule.GetWebhooks(r.Context(), tenantID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Webhooks fetched", hooks, nil)
}

func (h *ManagementHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	sess := identity.SessionFromRequest(r)
	hook, err := h.managementModule.CreateWebhook(r.Context(), sess.TenantID, req.URL, req.Events, sess.UserID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "Webhook created", hook, nil)
}

func (h *ManagementHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	if err := h.managementModule.DeleteWebhook(r.Context(), chi.URLParam(r, "id")); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Webhook deleted", map[string]bool{"deleted": true}, nil)
}

func (h *ManagementHandler) GetSecurityPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := identity.TenantIDFromContext(r.Context())
	orgID := r.URL.Query().Get("organization_id")
	policies, err := h.managementModule.GetSecurityPolicies(r.Context(), tenantID, orgID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Security policies fetched", policies, nil)
}

func (h *ManagementHandler) CreateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string                 `json:"name"`
		PolicyType     string                 `json:"policy_type"`
		OrganizationID string                 `json:"organization_id"`
		Configuration  map[string]interface{} `json:"configuration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	tenantID := identity.TenantIDFromContext(r.Context())
	policy, err := h.managementModule.CreateSecurityPolicy(r.Context(), tenantID, req.OrganizationID, req.Name, req.PolicyType, req.Configuration)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "Security policy created", policy, nil)
}

func (h *ManagementHandler) DeleteSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	if err := h.managementModule.DeleteSecurityPolicy(r.Context(), chi.URLParam(r, "id")); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Security policy deleted", map[string]bool{"deleted": true}, nil)
}

func (h *ManagementHandler) GetDomains(w http.ResponseWriter, r *http.Request) {
	tenantID := identity.TenantIDFromContext(r.Context())
	if tenantID == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	domains, err := h.managementModule.GetDomains(r.Context(), tenantID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Domains fetched", domains, nil)
}

func (h *ManagementHandler) RegisterDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	tenantID := identity.TenantIDFromContext(r.Context())
	domain, err := h.managementModule.RegisterDomain(r.Context(), tenantID, req.Domain)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "Domain registered", domain, nil)
}

func (h *ManagementHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	domain, err := h.managementModule.VerifyDomain(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Domain verified", domain, nil)
}

func (h *ManagementHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	if err := h.managementModule.DeleteDomain(r.Context(), chi.URLParam(r, "id")); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Domain deleted", map[string]bool{"deleted": true}, nil)
}

func (h *ManagementHandler) GetSsoConnections(w http.ResponseWriter, r *http.Request) {
	conns, err := h.managementModule.GetSsoConnections(r.Context(), chi.URLParam(r, "orgId"))
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "SSO connections fetched", conns, nil)
}

func (h *ManagementHandler) CreateSsoConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider  string `json:"provider"`
		Name      string `json:"name"`
		IssuerURL string `json:"issuer_url"`
		ClientID  string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	sess := identity.SessionFromRequest(r)
	conn, err := h.managementModule.CreateSsoConnection(r.Context(), chi.URLParam(r, "orgId"), req.Provider, req.Name, req.IssuerURL, req.ClientID, sess.UserID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "SSO connection created", conn, nil)
}

func (h *ManagementHandler) UpdateSsoConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.managementModule.UpdateSsoConnection(r.Context(), chi.URLParam(r, "id"), req.Enabled); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "SSO connection updated", nil, nil)
}

func (h *ManagementHandler) DeleteSsoConnection(w http.ResponseWriter, r *http.Request) {
	if err := h.managementModule.DeleteSsoConnection(r.Context(), chi.URLParam(r, "id")); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "SSO connection deleted", map[string]bool{"deleted": true}, nil)
}

func (h *ManagementHandler) GetScimConnections(w http.ResponseWriter, r *http.Request) {
	conns, err := h.managementModule.GetScimConnections(r.Context(), chi.URLParam(r, "orgId"))
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "SCIM connections fetched", conns, nil)
}

func (h *ManagementHandler) CreateScimConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Provider == "" {
		req.Provider = "generic"
	}
	conn, err := h.managementModule.CreateScimConnection(r.Context(), chi.URLParam(r, "orgId"), req.Provider)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "SCIM connection created", conn, nil)
}

func (h *ManagementHandler) RevokeScimConnection(w http.ResponseWriter, r *http.Request) {
	if err := h.managementModule.RevokeScimConnection(r.Context(), chi.URLParam(r, "id")); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "SCIM connection revoked", map[string]bool{"revoked": true}, nil)
}

func (h *ManagementHandler) GetNetworkRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.managementModule.GetNetworkRules(r.Context(), chi.URLParam(r, "orgId"))
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Network rules fetched", rules, nil)
}

func (h *ManagementHandler) CreateNetworkRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR        string `json:"cidr"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	rule, err := h.managementModule.CreateNetworkRule(r.Context(), chi.URLParam(r, "orgId"), req.CIDR, req.Description)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "Network rule created", rule, nil)
}

func (h *ManagementHandler) DeleteNetworkRule(w http.ResponseWriter, r *http.Request) {
	if err := h.managementModule.DeleteNetworkRule(r.Context(), chi.URLParam(r, "id")); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Network rule deleted", map[string]bool{"deleted": true}, nil)
}
