package aos

import "net/http"

// ManagementHandlers exposes admin/management HTTP handlers.
// Most handlers require session authentication and admin permission.
type ManagementHandlers struct{ h *HandlersAPI }

func (h *ManagementHandlers) CreateRole(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateRole(w, r)
}

func (h *ManagementHandlers) GetUsers(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetUsers(w, r)
}

func (h *ManagementHandlers) GetRoles(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetRoles(w, r)
}

func (h *ManagementHandlers) GetOrganizations(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetOrganizations(w, r)
}

func (h *ManagementHandlers) GetPermissions(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetPermissions(w, r)
}

func (h *ManagementHandlers) GetMemberships(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetMemberships(w, r)
}

func (h *ManagementHandlers) GetTenants(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetTenants(w, r)
}

func (h *ManagementHandlers) GetOAuthProviders(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetOAuthProviders(w, r)
}

func (h *ManagementHandlers) HandleProjects(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.HandleProjects(w, r)
}

func (h *ManagementHandlers) CreateTenant(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateTenant(w, r)
}

func (h *ManagementHandlers) UpdateRole(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.UpdateRole(w, r)
}

func (h *ManagementHandlers) DeleteRole(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.DeleteRole(w, r)
}

func (h *ManagementHandlers) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetRolePermissions(w, r)
}

func (h *ManagementHandlers) UpdateRolePermissions(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.UpdateRolePermissions(w, r)
}

func (h *ManagementHandlers) CreatePermission(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreatePermission(w, r)
}

func (h *ManagementHandlers) AssignMembership(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.AssignMembership(w, r)
}

func (h *ManagementHandlers) ConfigureOAuth(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.ConfigureOAuth(w, r)
}

func (h *ManagementHandlers) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetAuditLogs(w, r)
}

func (h *ManagementHandlers) GetApiKeys(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetApiKeys(w, r)
}

func (h *ManagementHandlers) CreateApiKey(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateApiKey(w, r)
}

func (h *ManagementHandlers) RevokeApiKey(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.RevokeApiKey(w, r)
}

func (h *ManagementHandlers) GetWebhooks(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetWebhooks(w, r)
}

func (h *ManagementHandlers) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateWebhook(w, r)
}

func (h *ManagementHandlers) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.DeleteWebhook(w, r)
}

func (h *ManagementHandlers) GetSecurityPolicies(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetSecurityPolicies(w, r)
}

func (h *ManagementHandlers) CreateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateSecurityPolicy(w, r)
}

func (h *ManagementHandlers) DeleteSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.DeleteSecurityPolicy(w, r)
}

func (h *ManagementHandlers) GetDomains(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetDomains(w, r)
}

func (h *ManagementHandlers) RegisterDomain(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.RegisterDomain(w, r)
}

func (h *ManagementHandlers) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.VerifyDomain(w, r)
}

func (h *ManagementHandlers) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.DeleteDomain(w, r)
}

func (h *ManagementHandlers) GetSsoConnections(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetSsoConnections(w, r)
}

func (h *ManagementHandlers) CreateSsoConnection(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateSsoConnection(w, r)
}

func (h *ManagementHandlers) UpdateSsoConnection(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.UpdateSsoConnection(w, r)
}

func (h *ManagementHandlers) DeleteSsoConnection(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.DeleteSsoConnection(w, r)
}

func (h *ManagementHandlers) GetScimConnections(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetScimConnections(w, r)
}

func (h *ManagementHandlers) CreateScimConnection(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateScimConnection(w, r)
}

func (h *ManagementHandlers) RevokeScimConnection(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.RevokeScimConnection(w, r)
}

func (h *ManagementHandlers) GetNetworkRules(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.GetNetworkRules(w, r)
}

func (h *ManagementHandlers) CreateNetworkRule(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.CreateNetworkRule(w, r)
}

func (h *ManagementHandlers) DeleteNetworkRule(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Management.DeleteNetworkRule(w, r)
}
