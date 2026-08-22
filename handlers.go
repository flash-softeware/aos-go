package aos

import (
	"net/http"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
)

// HandlersAPI exposes individual HTTP handlers. The host application owns URLs,
// HTTP methods, route prefixes, and middleware ordering.
type HandlersAPI struct {
	a *AOS
}

// Health reports SDK readiness. No authentication required.
func (h *HandlersAPI) Health(w http.ResponseWriter, r *http.Request) {
	response.SendSuccessResponse(w, http.StatusOK, "Healthy", map[string]string{"status": "ok"}, nil)
}

// Auth returns authentication-related handlers.
func (h *HandlersAPI) Auth() *AuthHandlers {
	return &AuthHandlers{h: h}
}

// MFA returns multi-factor authentication handlers.
func (h *HandlersAPI) MFA() *MFAHandlers {
	return &MFAHandlers{h: h}
}

// Passkey returns WebAuthn / passkey handlers.
func (h *HandlersAPI) Passkey() *PasskeyHandlers {
	return &PasskeyHandlers{h: h}
}

// OAuth returns social login handlers. Routes with {provider} require a router with path parameters.
func (h *HandlersAPI) OAuth() *OAuthHandlers {
	return &OAuthHandlers{h: h}
}

// Organizations returns organization management handlers.
func (h *HandlersAPI) Organizations() *OrganizationHandlers {
	return &OrganizationHandlers{h: h}
}

// IAM returns authorization handlers.
func (h *HandlersAPI) IAM() *IAMHandlers {
	return &IAMHandlers{h: h}
}

// Context returns portal/context handlers (legacy /v1/me/* behavior).
func (h *HandlersAPI) Context() *ContextHandlers {
	return &ContextHandlers{h: h}
}

// Management returns admin/management handlers. Most require session + admin permission.
func (h *HandlersAPI) Management() *ManagementHandlers {
	return &ManagementHandlers{h: h}
}

// AuthHandlers exposes authentication HTTP handlers.
type AuthHandlers struct{ h *HandlersAPI }

// Public handlers (no session required)

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.Login(w, r)
}

func (h *AuthHandlers) Register(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.User.Register(w, r)
}

func (h *AuthHandlers) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.ForgotPassword(w, r)
}

func (h *AuthHandlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.ResetPassword(w, r)
}

func (h *AuthHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.VerifyEmail(w, r)
}

func (h *AuthHandlers) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.AcceptInvite(w, r)
}

// SessionRequired handlers (wrap with sdk.Middleware().RequireSession())

func (h *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.Logout(w, r)
}

func (h *AuthHandlers) SetContext(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.SetContext(w, r)
}

// SwitchOrganization is deprecated; use SetContext.
func (h *AuthHandlers) SwitchOrganization(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.SwitchOrganization(w, r)
}

func (h *AuthHandlers) Me(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.Me(w, r)
}

func (h *AuthHandlers) ResendEmailVerification(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.ResendEmailVerification(w, r)
}

func (h *AuthHandlers) GetSessions(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.GetSessions(w, r)
}

func (h *AuthHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.RevokeSession(w, r)
}

func (h *AuthHandlers) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.RevokeAllSessions(w, r)
}

// MFAHandlers exposes MFA HTTP handlers.
type MFAHandlers struct{ h *HandlersAPI }

func (h *MFAHandlers) VerifyLogin(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.MfaVerifyLogin(w, r)
}

func (h *MFAHandlers) Status(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.GetMfaStatus(w, r)
}

func (h *MFAHandlers) EnrollStart(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.MfaEnrollStart(w, r)
}

func (h *MFAHandlers) EnrollVerify(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.MfaEnrollVerify(w, r)
}

func (h *MFAHandlers) Disable(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.MfaDisable(w, r)
}

// PasskeyHandlers exposes WebAuthn HTTP handlers.
type PasskeyHandlers struct{ h *HandlersAPI }

func (h *PasskeyHandlers) Authenticate(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.PasskeysAuthenticate(w, r)
}

func (h *PasskeyHandlers) AuthenticateVerify(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.PasskeysAuthenticateVerify(w, r)
}

func (h *PasskeyHandlers) RegisterOptions(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.PasskeysRegister(w, r)
}

func (h *PasskeyHandlers) RegisterVerify(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.PasskeysVerify(w, r)
}

func (h *PasskeyHandlers) List(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.GetPasskeys(w, r)
}

// OAuthHandlers exposes OAuth HTTP handlers.
type OAuthHandlers struct{ h *HandlersAPI }

func (h *OAuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.SocialLogin(w, r)
}

func (h *OAuthHandlers) Callback(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Auth.SocialCallback(w, r)
}

// OrganizationHandlers exposes organization HTTP handlers.
type OrganizationHandlers struct{ h *HandlersAPI }

func (h *OrganizationHandlers) Create(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Organization.Create(w, r)
}

func (h *OrganizationHandlers) Get(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Me.GetOrganization(w, r)
}

func (h *OrganizationHandlers) ListMembers(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Me.ListOrgMembersForOrg(w, r)
}

func (h *OrganizationHandlers) Activate(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Organization.Activate(w, r)
}

func (h *OrganizationHandlers) Update(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Organization.Update(w, r)
}

func (h *OrganizationHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Organization.Delete(w, r)
}

func (h *OrganizationHandlers) Invite(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Organization.Invite(w, r)
}

func (h *OrganizationHandlers) AddMember(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Organization.AddMember(w, r)
}

func (h *OrganizationHandlers) RemoveMember(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Organization.RemoveMember(w, r)
}

// IAMHandlers exposes authorization HTTP handlers.
type IAMHandlers struct{ h *HandlersAPI }

func (h *IAMHandlers) Can(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Authz.Can(w, r)
}

func (h *IAMHandlers) CheckPermission(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.IAM.CheckPermission(w, r)
}

// ContextHandlers exposes portal context HTTP handlers.
type ContextHandlers struct{ h *HandlersAPI }

func (h *ContextHandlers) Get(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Me.GetContext(w, r)
}

func (h *ContextHandlers) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Me.ListOrganizations(w, r)
}

func (h *ContextHandlers) ListPermissions(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Me.ListPermissions(w, r)
}

func (h *ContextHandlers) ListOrgMembers(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Me.ListOrgMembers(w, r)
}

func (h *ContextHandlers) Can(w http.ResponseWriter, r *http.Request) {
	h.h.a.app.HTTPHandlers.Me.Can(w, r)
}
