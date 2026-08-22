package main

import (
	aos "github.com/Esubalew-Sintie/aos-auth-go"
	"github.com/go-chi/chi/v5"
)

// mountAOSRoutes demonstrates default /v1/* wiring. Host apps own URLs — copy and edit as needed.
func mountAOSRoutes(r chi.Router, sdk *aos.AOS) {
	h := sdk.Handlers()
	requireSession := sdk.Middleware().RequireSession()
	requireManagement := sdk.Middleware().RequirePermission("user.read")

	r.Route("/v1/auth", func(r chi.Router) {
		r.Post("/register", h.Auth().Register)
		r.Post("/login", h.Auth().Login)
		r.Post("/mfa/verify", h.MFA().VerifyLogin)
		r.Post("/password/forgot", h.Auth().ForgotPassword)
		r.Post("/password/reset", h.Auth().ResetPassword)
		r.Get("/email/verify", h.Auth().VerifyEmail)
		r.Post("/invitations/accept", h.Auth().AcceptInvite)
		r.Get("/oauth/{provider}", h.OAuth().Login)
		r.Get("/oauth/{provider}/callback", h.OAuth().Callback)

		r.Group(func(r chi.Router) {
			r.Use(requireSession)
			r.Post("/logout", h.Auth().Logout)
			r.Get("/me", h.Auth().Me)
			r.Post("/email/resend", h.Auth().ResendEmailVerification)
			r.Get("/context", h.Context().Get)
			r.Put("/context", h.Auth().SetContext)
		})
	})

	r.Route("/v1/users", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/me", h.Auth().Me)
	})

	r.Route("/v1/sessions", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/", h.Auth().GetSessions)
		r.Delete("/", h.Auth().RevokeAllSessions)
		r.Delete("/{id}", h.Auth().RevokeSession)
	})

	r.Route("/v1/mfa", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/", h.MFA().Status)
		r.Post("/enroll", h.MFA().EnrollStart)
		r.Post("/enroll/verify", h.MFA().EnrollVerify)
		r.Post("/disable", h.MFA().Disable)
	})

	r.Route("/v1/passkeys", func(r chi.Router) {
		r.Post("/authenticate", h.Passkey().Authenticate)
		r.Post("/authenticate/verify", h.Passkey().AuthenticateVerify)

		r.Group(func(r chi.Router) {
			r.Use(requireSession)
			r.Get("/register", h.Passkey().RegisterOptions)
			r.Post("/register/verify", h.Passkey().RegisterVerify)
			r.Get("/", h.Passkey().List)
		})
	})

	r.Route("/v1/organizations", func(r chi.Router) {
		r.Use(requireSession)

		r.Get("/", h.Context().ListOrganizations)
		r.Post("/", h.Organizations().Create)
		r.Get("/{id}", h.Organizations().Get)
		r.Patch("/{id}", h.Organizations().Update)
		r.Delete("/{id}", h.Organizations().Delete)

		r.Get("/{id}/members", h.Organizations().ListMembers)
		r.Post("/{id}/members", h.Organizations().AddMember)
		r.Delete("/{id}/members/{userId}", h.Organizations().RemoveMember)

		r.Post("/{id}/invitations", h.Organizations().Invite)
		r.Post("/{id}/activate", h.Organizations().Activate)

		r.Get("/{id}/roles", h.Management().GetRoles)
		r.Post("/{id}/roles", h.Management().CreateRole)
		r.Get("/{id}/permissions", h.Management().GetPermissions)
	})

	r.Route("/v1/roles", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/", h.Management().GetRoles)
		r.Post("/", h.Management().CreateRole)
		r.Put("/{id}", h.Management().UpdateRole)
		r.Delete("/{id}", h.Management().DeleteRole)
		r.Get("/{id}/permissions", h.Management().GetRolePermissions)
		r.Put("/{id}/permissions", h.Management().UpdateRolePermissions)
	})

	r.Route("/v1/permissions", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/", h.Management().GetPermissions)
		r.Post("/", h.Management().CreatePermission)
	})

	r.Route("/v1/authorization", func(r chi.Router) {
		r.Use(requireSession)
		r.Post("/check", h.IAM().CheckPermission)
		r.Post("/check/batch", h.Context().Can)
	})

	r.Route("/v1/api-keys", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/", h.Management().GetApiKeys)
		r.Post("/", h.Management().CreateApiKey)
		r.Delete("/{id}", h.Management().RevokeApiKey)
	})

	r.Route("/v1/webhooks", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/", h.Management().GetWebhooks)
		r.Post("/", h.Management().CreateWebhook)
		r.Delete("/{id}", h.Management().DeleteWebhook)
	})

	r.Route("/v1/domains", func(r chi.Router) {
		r.Use(requireSession)
		r.Get("/", h.Management().GetDomains)
		r.Post("/", h.Management().RegisterDomain)
		r.Post("/{id}/verification", h.Management().VerifyDomain)
		r.Delete("/{id}", h.Management().DeleteDomain)
	})

	r.Route("/v1/management", func(r chi.Router) {
		r.Use(requireSession)
		r.Use(requireManagement)

		r.Get("/users", h.Management().GetUsers)
		r.Get("/roles", h.Management().GetRoles)
		r.Get("/permissions", h.Management().GetPermissions)
		r.Get("/memberships", h.Management().GetMemberships)
		r.Get("/organizations", h.Management().GetOrganizations)
		r.Get("/tenants", h.Management().GetTenants)
		r.Get("/oauth-providers", h.Management().GetOAuthProviders)
		r.Get("/audit-logs", h.Management().GetAuditLogs)

		r.Post("/memberships", h.Management().AssignMembership)
		r.Post("/oauth-providers", h.Management().ConfigureOAuth)
		r.Post("/tenants", h.Management().CreateTenant)

		r.Post("/organizations", h.Organizations().Create)
		r.Put("/organizations/{id}", h.Organizations().Update)
		r.Delete("/organizations/{id}", h.Organizations().Delete)

		r.Get("/organizations/{orgId}/workspaces", h.Management().HandleProjects)
		r.Post("/organizations/{orgId}/workspaces", h.Management().HandleProjects)
		r.Put("/workspaces/{id}", h.Management().HandleProjects)
		r.Delete("/workspaces/{id}", h.Management().HandleProjects)

		r.Get("/organizations/{orgId}/sso-connections", h.Management().GetSsoConnections)
		r.Post("/organizations/{orgId}/sso-connections", h.Management().CreateSsoConnection)
		r.Put("/sso-connections/{id}", h.Management().UpdateSsoConnection)
		r.Delete("/sso-connections/{id}", h.Management().DeleteSsoConnection)

		r.Get("/organizations/{orgId}/scim-connections", h.Management().GetScimConnections)
		r.Post("/organizations/{orgId}/scim-connections", h.Management().CreateScimConnection)
		r.Delete("/scim-connections/{id}", h.Management().RevokeScimConnection)

		r.Get("/organizations/{orgId}/network-rules", h.Management().GetNetworkRules)
		r.Post("/organizations/{orgId}/network-rules", h.Management().CreateNetworkRule)
		r.Delete("/network-rules/{id}", h.Management().DeleteNetworkRule)

		r.Get("/security-policies", h.Management().GetSecurityPolicies)
		r.Post("/security-policies", h.Management().CreateSecurityPolicy)
		r.Delete("/security-policies/{id}", h.Management().DeleteSecurityPolicy)
	})
}
