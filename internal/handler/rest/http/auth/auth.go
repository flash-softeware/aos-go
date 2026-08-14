package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	dto "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/request"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/auth"
	meModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/me"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
	"github.com/go-chi/chi/v5"
)

type AuthHandler struct {
	authModule *auth.Module
	meModule   *meModule.Module
}

func NewAuthHandler(authModule *auth.Module, me *meModule.Module) *AuthHandler {
	return &AuthHandler{authModule: authModule, meModule: me}
}

func (h *AuthHandler) authSuccessPayloadFromToken(ctx context.Context, userID, sessionToken string) map[string]interface{} {
	return map[string]interface{}{
		"session_token": sessionToken,
		"user_id":       userID,
	}
}

func (h *AuthHandler) authSuccessPayload(ctx context.Context, userID, sessionToken, sessionOrgID string) map[string]interface{} {
	return h.authSuccessPayloadFromToken(ctx, userID, sessionToken)
}

func (h *AuthHandler) extractToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); header != "" {
		if len(header) > 7 && header[:7] == "Bearer " {
			return header[7:]
		}
	}
	if cookie, err := r.Cookie("aos_session"); err == nil {
		return cookie.Value
	}
	return ""
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	result, err := h.authModule.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrInvalidCredentials)
		return
	}
	if result.MfaRequired {
		response.SendSuccessResponse(w, http.StatusOK, "MFA required", map[string]interface{}{
			"mfa_required": true,
			"mfa_token":    result.MfaToken,
			"user_id":      result.UserID,
		}, nil)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Login successful", h.authSuccessPayloadFromToken(r.Context(), result.UserID, result.SessionToken), nil)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token := h.extractToken(r)
	if token == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}
	if err := h.authModule.Logout(r.Context(), token); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Logged out", nil, nil)
}

func (h *AuthHandler) SwitchOrganization(w http.ResponseWriter, r *http.Request) {
	h.SetContext(w, r)
}

func (h *AuthHandler) SetContext(w http.ResponseWriter, r *http.Request) {
	token := h.extractToken(r)
	if token == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	var req dto.SetContextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	resourceID := req.ResourceID
	if resourceID == "" {
		resourceID = req.OrganizationID
	}
	if resourceID == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	if err := h.authModule.SetActiveResource(r.Context(), token, resourceID); err != nil {
		response.SendErrorResponse(w, errors.ErrForbidden)
		return
	}

	sess, err := h.authModule.ValidateSessionFull(r.Context(), token)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}

	response.SendSuccessResponse(w, http.StatusOK, "Active resource updated", map[string]interface{}{
		"session_token":        token,
		"user_id":              sess.UserID,
		"active_resource_id":   sess.ActiveResourceID,
		"organization_id":      sess.ActiveResourceID,
		"role_id":              sess.RoleID,
	}, nil)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	sess := identity.SessionFromRequest(r)
	if sess.UserID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	user, err := h.authModule.CurrentUser(r.Context(), sess.UserID)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrNotFound)
		return
	}

	response.SendSuccessResponse(w, http.StatusOK, "Current user", map[string]interface{}{
		"user": user,
		"session": map[string]string{
			"user_id":            sess.UserID,
			"tenant_id":          sess.TenantID,
			"active_resource_id": sess.OrgID,
			"organization_id":    sess.OrgID,
			"role_id":            sess.RoleID,
		},
	}, nil)
}

func (h *AuthHandler) PasskeysRegister(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	options, err := h.authModule.GenerateRegistrationOptions(r.Context(), userID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Registration options generated", options, nil)
}

func (h *AuthHandler) PasskeysVerify(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	res, err := h.authModule.VerifyRegistration(r.Context(), userID, body)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Passkey registered successfully", res, nil)
}

func (h *AuthHandler) PasskeysAuthenticate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	options, err := h.authModule.GenerateAuthenticationOptions(r.Context(), req.Email)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Authentication options generated", options, nil)
}

func (h *AuthHandler) PasskeysAuthenticateVerify(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))

	body, err := io.ReadAll(r.Body)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	credentialBody := body
	if email == "" {
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			response.SendErrorResponse(w, errors.ErrBadRequest)
			return
		}

		if rawEmail, ok := payload["email"]; ok {
			_ = json.Unmarshal(rawEmail, &email)
			delete(payload, "email")
		}
		if email == "" {
			response.SendErrorResponse(w, errors.ErrBadRequest)
			return
		}

		credentialBody, err = json.Marshal(payload)
		if err != nil {
			response.SendErrorResponse(w, errors.ErrBadRequest)
			return
		}
	}

	result, err := h.authModule.VerifyAuthentication(r.Context(), email, credentialBody)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	userID := result["user_id"]
	sessionToken := result["session_token"]
	response.SendSuccessResponse(w, http.StatusOK, "Passkey authentication successful", h.authSuccessPayloadFromToken(r.Context(), userID, sessionToken), nil)
}

func (h *AuthHandler) GetPasskeys(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	if userID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	keys, err := h.authModule.GetPasskeys(r.Context(), userID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Passkeys retrieved", keys, nil)
}

func (h *AuthHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	sessions, err := h.authModule.ListSessions(r.Context(), userID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Sessions retrieved", sessions, nil)
}

func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	sessionID := chi.URLParam(r, "id")
	if err := h.authModule.RevokeSession(r.Context(), userID, sessionID); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Session revoked", map[string]string{"message": "Session revoked"}, nil)
}

func (h *AuthHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userID := identity.UserIDFromContext(r.Context())
	token := h.extractToken(r)
	if err := h.authModule.RevokeAllSessions(r.Context(), userID, token); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Sessions revoked", map[string]string{"message": "All other sessions revoked"}, nil)
}

func (h *AuthHandler) GetMfaStatus(w http.ResponseWriter, r *http.Request) {
	sess := identity.SessionFromRequest(r)
	status, err := h.authModule.GetMfaStatus(r.Context(), sess.UserID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "MFA status", status, nil)
}

func (h *AuthHandler) MfaEnrollStart(w http.ResponseWriter, r *http.Request) {
	sess := identity.SessionFromRequest(r)
	user, err := h.authModule.CurrentUser(r.Context(), sess.UserID)
	email := "user@example.com"
	if err == nil && user != nil {
		email = user.Email
	}
	result, err := h.authModule.MfaEnrollStart(r.Context(), sess.UserID, email)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "MFA enrollment started", result, nil)
}

func (h *AuthHandler) MfaEnrollVerify(w http.ResponseWriter, r *http.Request) {
	sess := identity.SessionFromRequest(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	result, err := h.authModule.MfaEnrollVerify(r.Context(), sess.UserID, req.Code)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "MFA enabled", result, nil)
}

func (h *AuthHandler) MfaDisable(w http.ResponseWriter, r *http.Request) {
	sess := identity.SessionFromRequest(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.authModule.MfaDisable(r.Context(), sess.UserID, req.Code); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "MFA disabled", map[string]bool{"disabled": true}, nil)
}

func (h *AuthHandler) MfaVerifyLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MfaToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	result, err := h.authModule.MfaVerifyLogin(r.Context(), req.MfaToken, req.Code)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrInvalidCredentials)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "MFA verified", h.authSuccessPayloadFromToken(r.Context(), result["user_id"], result["session_token"]), nil)
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	result, err := h.authModule.ForgotPassword(r.Context(), req.Email)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, result["message"], result, nil)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" || req.Password == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	if err := h.authModule.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		response.SendErrorResponse(w, errors.ErrInvalidCredentials)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Password updated successfully", map[string]string{"message": "Password updated successfully"}, nil)
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	result, err := h.authModule.VerifyEmail(r.Context(), token)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrInvalidCredentials)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Email verified", result, nil)
}

func (h *AuthHandler) ResendEmailVerification(w http.ResponseWriter, r *http.Request) {
	sess := identity.SessionFromRequest(r)
	result, err := h.authModule.ResendEmailVerification(r.Context(), sess.UserID)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, result["message"], result, nil)
}

func (h *AuthHandler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		Password  string `json:"password"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" || req.Password == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}
	result, err := h.authModule.AcceptInvitation(r.Context(), req.Token, req.Password, req.FirstName, req.LastName)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrInvalidCredentials)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Invitation accepted", h.authSuccessPayloadFromToken(r.Context(), result.UserID, result.SessionToken), nil)
}

func (h *AuthHandler) SocialLogin(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	tenantID := r.URL.Query().Get("tenant_id")
	callbackURL := r.URL.Query().Get("callback_url")
	if tenantID == "" || callbackURL == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	backendCallback := scheme + "://" + r.Host + "/aos/v1/auth/social/" + provider + "/callback"

	loginURL, err := h.authModule.SocialLoginURL(r.Context(), provider, tenantID, callbackURL, backendCallback)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *AuthHandler) SocialCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	backendCallback := scheme + "://" + r.Host + "/aos/v1/auth/social/" + provider + "/callback"

	result, callbackURL, err := h.authModule.SocialLoginCallback(r.Context(), provider, code, state, backendCallback)
	if err != nil {
		response.SendErrorResponse(w, errors.ErrInvalidCredentials)
		return
	}
	http.Redirect(w, r, auth.RedirectWithSession(callbackURL, result.SessionToken), http.StatusFound)
}
