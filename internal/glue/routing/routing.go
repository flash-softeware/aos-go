package routing

import (
	"net/http"

	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/handler/rest/http/auth"
	"github.com/aos/sdk-go/internal/handler/rest/http/authz"
	"github.com/aos/sdk-go/internal/handler/rest/http/iam"
	"github.com/aos/sdk-go/internal/handler/rest/http/me"
	"github.com/aos/sdk-go/internal/handler/rest/http/management"
	"github.com/aos/sdk-go/internal/handler/rest/http/organization"
	"github.com/aos/sdk-go/internal/handler/rest/http/user"
	"github.com/go-chi/chi/v5"
)

type Router struct {
	AuthHandler         *auth.AuthHandler
	UserHandler         *user.UserHandler
	OrganizationHandler *organization.OrganizationHandler
	IamHandler          *iam.IamHandler
	AuthzHandler        *authz.Handler
	ManagementHandler   *management.ManagementHandler
	MeHandler           *me.MeHandler
}

func NewRouter(
	authHandler *auth.AuthHandler,
	userHandler *user.UserHandler,
	orgHandler *organization.OrganizationHandler,
	iamHandler *iam.IamHandler,
	authzHandler *authz.Handler,
	mgtHandler *management.ManagementHandler,
	meHandler *me.MeHandler,
) *Router {
	return &Router{
		AuthHandler:         authHandler,
		UserHandler:         userHandler,
		OrganizationHandler: orgHandler,
		IamHandler:          iamHandler,
		AuthzHandler:        authzHandler,
		ManagementHandler:   mgtHandler,
		MeHandler:           meHandler,
	}
}

func (router *Router) ServeHTTP(requireAuth, requireAdmin func(http.Handler) http.Handler) http.Handler {
	r := chi.NewRouter()

	r.Get("/v1/health", func(w http.ResponseWriter, req *http.Request) {
		response.SendSuccessResponse(w, http.StatusOK, "Healthy", map[string]string{"status": "ok"}, nil)
	})

	// Public auth routes
	r.Post("/v1/auth/login", router.AuthHandler.Login)
	r.Post("/v1/auth/register", router.UserHandler.Register)
	r.Post("/v1/auth/mfa/verify", router.AuthHandler.MfaVerifyLogin)
	r.Post("/v1/auth/passkeys/authenticate", router.AuthHandler.PasskeysAuthenticate)
	r.Post("/v1/auth/passkeys/authenticate/verify", router.AuthHandler.PasskeysAuthenticateVerify)
	r.Post("/v1/auth/password/forgot", router.AuthHandler.ForgotPassword)
	r.Post("/v1/auth/password/reset", router.AuthHandler.ResetPassword)
	r.Get("/v1/auth/verify/email", router.AuthHandler.VerifyEmail)
	r.Post("/v1/auth/invites/accept", router.AuthHandler.AcceptInvite)
	r.Get("/v1/auth/social/{provider}", router.AuthHandler.SocialLogin)
	r.Get("/v1/auth/social/{provider}/callback", router.AuthHandler.SocialCallback)

	// Protected auth routes
	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		r.Post("/v1/auth/logout", router.AuthHandler.Logout)
		r.Post("/v1/auth/set-context", router.AuthHandler.SetContext)
		r.Post("/v1/auth/switch-organization", router.AuthHandler.SwitchOrganization)
		r.Get("/v1/auth/me", router.AuthHandler.Me)
		r.Post("/v1/auth/verify/email/resend", router.AuthHandler.ResendEmailVerification)
		r.Get("/v1/auth/passkeys/register", router.AuthHandler.PasskeysRegister)
		r.Post("/v1/auth/passkeys/register/verify", router.AuthHandler.PasskeysVerify)
		r.Get("/v1/auth/passkeys", router.AuthHandler.GetPasskeys)
		r.Get("/v1/auth/sessions", router.AuthHandler.GetSessions)
		r.Delete("/v1/auth/sessions/{id}", router.AuthHandler.RevokeSession)
		r.Delete("/v1/auth/sessions", router.AuthHandler.RevokeAllSessions)
		r.Get("/v1/auth/mfa", router.AuthHandler.GetMfaStatus)
		r.Post("/v1/auth/mfa/enroll", router.AuthHandler.MfaEnrollStart)
		r.Post("/v1/auth/mfa/enroll/verify", router.AuthHandler.MfaEnrollVerify)
		r.Post("/v1/auth/mfa/disable", router.AuthHandler.MfaDisable)
	})

	// Authorization (core SDK)
	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		r.Post("/v1/authz/can", router.AuthzHandler.Can)
	})

	// Deprecated reference-portal routes (backward compatibility)
	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		r.Get("/v1/me/organizations", router.MeHandler.ListOrganizations)
		r.Get("/v1/me/permissions", router.MeHandler.ListPermissions)
		r.Get("/v1/me/members", router.MeHandler.ListOrgMembers)
		r.Post("/v1/me/can", router.MeHandler.Can)
	})

	// Protected admin routes
	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		if requireAdmin != nil {
			r.Use(requireAdmin)
		}

		r.Get("/v1/admin/users", router.ManagementHandler.GetUsers)
		r.Get("/v1/admin/roles", router.ManagementHandler.GetRoles)
		r.Get("/v1/admin/organizations", router.ManagementHandler.GetOrganizations)
		r.Get("/v1/admin/permissions", router.ManagementHandler.GetPermissions)
		r.Get("/v1/admin/memberships", router.ManagementHandler.GetMemberships)
		r.Get("/v1/admin/tenants", router.ManagementHandler.GetTenants)
		r.Get("/v1/admin/oauth-providers", router.ManagementHandler.GetOAuthProviders)

		r.Post("/v1/admin/organizations", router.OrganizationHandler.Create)
		r.Put("/v1/admin/organizations/{id}", router.OrganizationHandler.Update)
		r.Delete("/v1/admin/organizations/{id}", router.OrganizationHandler.Delete)
		r.Post("/v1/admin/organizations/{id}/invite", router.OrganizationHandler.Invite)
		r.Post("/v1/admin/organizations/{id}/members", router.OrganizationHandler.AddMember)
		r.Delete("/v1/admin/organizations/{id}/members/{userId}", router.OrganizationHandler.RemoveMember)

		r.Post("/v1/admin/organizations/{orgId}/projects", router.ManagementHandler.HandleProjects)
		r.Get("/v1/admin/organizations/{orgId}/projects", router.ManagementHandler.HandleProjects)
		r.Put("/v1/admin/projects/{id}", router.ManagementHandler.HandleProjects)
		r.Delete("/v1/admin/projects/{id}", router.ManagementHandler.HandleProjects)

		r.Post("/v1/admin/tenants", router.ManagementHandler.CreateTenant)
		r.Post("/v1/admin/roles", router.ManagementHandler.CreateRole)
		r.Put("/v1/admin/roles/{id}", router.ManagementHandler.UpdateRole)
		r.Delete("/v1/admin/roles/{id}", router.ManagementHandler.DeleteRole)
		r.Get("/v1/admin/roles/{id}/permissions", router.ManagementHandler.GetRolePermissions)
		r.Put("/v1/admin/roles/{id}/permissions", router.ManagementHandler.UpdateRolePermissions)
		r.Post("/v1/admin/permissions", router.ManagementHandler.CreatePermission)
		r.Post("/v1/admin/memberships/assign", router.ManagementHandler.AssignMembership)
		r.Post("/v1/admin/oauth-providers", router.ManagementHandler.ConfigureOAuth)
		r.Post("/v1/admin/can", router.IamHandler.CheckPermission)

		r.Get("/v1/admin/audit-logs", router.ManagementHandler.GetAuditLogs)
		r.Get("/v1/admin/api-keys", router.ManagementHandler.GetApiKeys)
		r.Post("/v1/admin/api-keys", router.ManagementHandler.CreateApiKey)
		r.Delete("/v1/admin/api-keys/{id}", router.ManagementHandler.RevokeApiKey)
		r.Get("/v1/admin/webhooks", router.ManagementHandler.GetWebhooks)
		r.Post("/v1/admin/webhooks", router.ManagementHandler.CreateWebhook)
		r.Delete("/v1/admin/webhooks/{id}", router.ManagementHandler.DeleteWebhook)
		r.Get("/v1/admin/security-policies", router.ManagementHandler.GetSecurityPolicies)
		r.Post("/v1/admin/security-policies", router.ManagementHandler.CreateSecurityPolicy)
		r.Delete("/v1/admin/security-policies/{id}", router.ManagementHandler.DeleteSecurityPolicy)
		r.Get("/v1/admin/domains", router.ManagementHandler.GetDomains)
		r.Post("/v1/admin/domains", router.ManagementHandler.RegisterDomain)
		r.Post("/v1/admin/domains/{id}/verify", router.ManagementHandler.VerifyDomain)
		r.Delete("/v1/admin/domains/{id}", router.ManagementHandler.DeleteDomain)
		r.Get("/v1/admin/organizations/{orgId}/sso-connections", router.ManagementHandler.GetSsoConnections)
		r.Post("/v1/admin/organizations/{orgId}/sso-connections", router.ManagementHandler.CreateSsoConnection)
		r.Put("/v1/admin/sso-connections/{id}", router.ManagementHandler.UpdateSsoConnection)
		r.Delete("/v1/admin/sso-connections/{id}", router.ManagementHandler.DeleteSsoConnection)
		r.Get("/v1/admin/organizations/{orgId}/scim-connections", router.ManagementHandler.GetScimConnections)
		r.Post("/v1/admin/organizations/{orgId}/scim-connections", router.ManagementHandler.CreateScimConnection)
		r.Delete("/v1/admin/scim-connections/{id}", router.ManagementHandler.RevokeScimConnection)
		r.Get("/v1/admin/organizations/{orgId}/network-rules", router.ManagementHandler.GetNetworkRules)
		r.Post("/v1/admin/organizations/{orgId}/network-rules", router.ManagementHandler.CreateNetworkRule)
		r.Delete("/v1/admin/network-rules/{id}", router.ManagementHandler.DeleteNetworkRule)
	})

	return r
}
