package auth

import (
	"context"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/oauth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/session"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/crypto"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/webauthn"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

type MFAOptions struct {
	Issuer            string
	RecoveryCodeCount int
}

type Module struct {
	store     storage.Storage
	providers *provider.Registry
	sessions  *session.Service
	webauthn  *webauthn.Service
	mfaBox    *crypto.SecretBox
	mfaOpts   MFAOptions
	orgOpts   OrganizationOptions

	cachedInstallationID string
}

type Session struct {
	UserID                string
	TenantID              string
	ActiveResourceIAMID   string // iam_resources.id — internal authorization scope
	ActiveOrganizationID  string // business org UUID — public API
	// ActiveResourceID is the business organization UUID when orgs are enabled.
	ActiveResourceID string
	RoleID           string
	// OrgID is deprecated; use ActiveOrganizationID.
	OrgID string
}

type LoginResult struct {
	SessionToken string
	UserID       string
	MfaRequired  bool
	MfaToken     string
}

func New(store storage.Storage, providers *provider.Registry, webauthnSvc *webauthn.Service, mfaBox *crypto.SecretBox, mfaOpts MFAOptions, orgOpts OrganizationOptions) *Module {
	if mfaOpts.Issuer == "" {
		mfaOpts.Issuer = "AOS IDaaS"
	}
	if mfaOpts.RecoveryCodeCount <= 0 {
		mfaOpts.RecoveryCodeCount = 8
	}
	return &Module{
		store:     store,
		providers: providers,
		sessions:  session.New(store),
		webauthn:  webauthnSvc,
		mfaBox:    mfaBox,
		mfaOpts:   mfaOpts,
		orgOpts:   orgOpts,
	}
}

func (m *Module) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	if m.providers == nil || m.providers.Password == nil {
		return nil, aoserrors.ErrPasswordAuthNotEnabled
	}

	result, err := m.providers.Password.Login(ctx, email, password)
	if err != nil {
		return nil, err
	}

	enabled, verified, err := m.store.Mfa().Status(ctx, result.UserID)
	if err != nil {
		return nil, err
	}
	if enabled && verified && m.mfaBox != nil {
		mfaToken, err := m.CreateMfaLoginChallenge(ctx, result.UserID)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			MfaRequired: true,
			MfaToken:    mfaToken,
			UserID:      result.UserID,
		}, nil
	}

	_ = m.autoSetActiveOrganization(ctx, result.SessionToken, result.UserID)

	return &LoginResult{
		SessionToken: result.SessionToken,
		UserID:       result.UserID,
	}, nil
}

func (m *Module) SocialLoginURL(ctx context.Context, providerName, tenantID, callbackURL, backendCallbackURL string) (string, error) {
	if m.providers == nil || m.providers.OAuth == nil {
		return "", aoserrors.ErrOAuthAuthNotEnabled
	}
	return m.providers.OAuth.LoginURL(ctx, providerName, tenantID, callbackURL, backendCallbackURL)
}

func (m *Module) SocialLoginCallback(ctx context.Context, providerName, code, state, backendCallbackURL string) (*LoginResult, string, error) {
	if m.providers == nil || m.providers.OAuth == nil {
		return nil, "", aoserrors.ErrOAuthAuthNotEnabled
	}
	result, callback, err := m.providers.OAuth.Callback(ctx, providerName, code, state, backendCallbackURL)
	if err != nil {
		return nil, "", err
	}
	_ = m.autoSetActiveOrganization(ctx, result.SessionToken, result.UserID)

	return &LoginResult{
		SessionToken: result.SessionToken,
		UserID:       result.UserID,
	}, callback, nil
}

func RedirectWithSession(callbackURL, sessionToken string) string {
	return oauth.RedirectWithSession(callbackURL, sessionToken)
}

func (m *Module) createSession(ctx context.Context, userID string) (string, error) {
	return m.sessions.Create(ctx, userID)
}

func (m *Module) SetActiveResource(ctx context.Context, sessionToken, resourceID string) error {
	if resourceID == "" {
		return aoserrors.ErrResourceIDRequired
	}
	if !m.orgOpts.Enabled {
		return aoserrors.ErrOrganizationsDisabled
	}

	sess, err := m.ValidateSessionFull(ctx, sessionToken)
	if err != nil {
		return err
	}

	ok, err := m.store.Memberships().HasOnResource(ctx, sess.UserID, resourceID)
	if err != nil {
		return err
	}
	if !ok {
		return aoserrors.ErrNotMemberOfResource
	}

	res, err := m.store.Resources().GetByBusinessID(ctx, "ORGANIZATION", resourceID)
	if err != nil {
		return err
	}

	return m.setActiveResourceIAM(ctx, sessionToken, res.ID)
}

func (m *Module) SwitchOrganization(ctx context.Context, sessionToken, orgID string) error {
	return m.SetActiveResource(ctx, sessionToken, orgID)
}

func (m *Module) ValidateSession(ctx context.Context, sessionToken string) (string, error) {
	sess, err := m.ValidateSessionFull(ctx, sessionToken)
	if err != nil {
		return "", err
	}
	return sess.UserID, nil
}

func (m *Module) ValidateSessionFull(ctx context.Context, sessionToken string) (*Session, error) {
	s, err := m.store.Sessions().GetByTokenHash(ctx, session.HashToken(sessionToken))
	if err != nil {
		return nil, aoserrors.ErrSessionInvalid
	}
	sess, err := m.enrichSession(ctx, s)
	if err != nil {
		return nil, err
	}
	sess.ActiveResourceID = sess.ActiveOrganizationID
	return sess, nil
}

func (m *Module) Logout(ctx context.Context, sessionToken string) error {
	return m.store.Sessions().Delete(ctx, session.HashToken(sessionToken))
}

func (m *Module) CurrentUser(ctx context.Context, userID string) (*response.User, error) {
	u, err := m.store.Users().GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &response.User{
		ID:        u.ID,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Status:    u.Status,
	}, nil
}

func (m *Module) GetPasskeys(ctx context.Context, userID string) ([]response.Passkey, error) {
	return m.store.Passkeys().List(ctx, userID)
}

func (m *Module) ListSessions(ctx context.Context, userID string) ([]response.UserSession, error) {
	return m.store.Sessions().ListByUser(ctx, userID)
}

func (m *Module) RevokeSession(ctx context.Context, userID, sessionID string) error {
	return m.store.Sessions().RevokeByID(ctx, userID, sessionID)
}

func (m *Module) RevokeAllSessions(ctx context.Context, userID, currentSessionToken string) error {
	exceptHash := ""
	if currentSessionToken != "" {
		exceptHash = session.HashToken(currentSessionToken)
	}
	return m.store.Sessions().DeleteUserSessions(ctx, userID, exceptHash)
}

func hashToken(sessionToken string) string {
	return session.HashToken(sessionToken)
}
