package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/platform/webauthn"
	"github.com/aos/sdk-go/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Module struct {
	store    storage.Repository
	webauthn *webauthn.Service
}

type Session struct {
	UserID           string
	TenantID         string
	ActiveResourceID string
	RoleID           string
	// OrgID mirrors ActiveResourceID for backward compatibility.
	OrgID string
}

type LoginResult struct {
	SessionToken string
	UserID       string
	MfaRequired  bool
	MfaToken     string
}

func New(store storage.Repository, webauthnSvc *webauthn.Service) *Module {
	return &Module{store: store, webauthn: webauthnSvc}
}

func (m *Module) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	userID, hash, err := m.store.GetUserAuth(ctx, email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	enabled, verified, err := m.store.GetMfaStatus(ctx, userID)
	if err != nil {
		return nil, err
	}
	if enabled && verified {
		mfaToken, err := m.CreateMfaLoginChallenge(ctx, userID)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			MfaRequired: true,
			MfaToken:    mfaToken,
			UserID:      userID,
		}, nil
	}

	sessionToken, err := m.createSession(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		SessionToken: sessionToken,
		UserID:       userID,
	}, nil
}

func (m *Module) resolveSessionOrg(ctx context.Context, userID string) (orgID, roleID string) {
	orgs, err := m.store.GetUserOrganizations(ctx, userID)
	if err != nil || len(orgs) != 1 {
		return "", ""
	}
	return orgs[0].ID, orgs[0].RoleID
}

func (m *Module) createSession(ctx context.Context, userID string) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	sessionToken := uuid.New().String()
	tokenHash := hashToken(sessionToken)
	expiresAt := time.Now().Add(24 * time.Hour)
	tenantID, _ := m.store.GetUserDefaultTenant(ctx, userID)
	orgID, roleID := m.resolveSessionOrg(ctx, userID)

	if err := m.store.InsertSession(ctx, tx, userID, tenantID, orgID, roleID, tokenHash, expiresAt); err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	return sessionToken, nil
}

func (m *Module) SetActiveResource(ctx context.Context, sessionToken, resourceID string) error {
	if resourceID == "" {
		return errors.New("resource_id is required")
	}

	sess, err := m.ValidateSessionFull(ctx, sessionToken)
	if err != nil {
		return err
	}

	ok, err := m.store.UserHasResourceMembership(ctx, sess.UserID, resourceID)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not a member of this resource")
	}

	roleID, _ := m.store.GetRoleIDForUserOnResource(ctx, sess.UserID, resourceID)
	tokenHash := hashToken(sessionToken)

	if isOrg, _ := m.store.UserHasOrgMembership(ctx, sess.UserID, resourceID); isOrg {
		return m.store.UpdateSessionOrganization(ctx, tokenHash, resourceID, roleID)
	}
	return m.store.UpdateSessionContext(ctx, tokenHash, resourceID, roleID)
}

// SwitchOrganization sets the active resource when it is an organization (deprecated name).
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
	tokenHash := hashToken(sessionToken)
	userID, tenantID, activeResourceID, roleID, err := m.store.GetSessionByToken(ctx, tokenHash)
	if err != nil {
		return nil, errors.New("invalid or expired session")
	}
	return &Session{
		UserID:           userID,
		TenantID:         tenantID,
		ActiveResourceID: activeResourceID,
		OrgID:            activeResourceID,
		RoleID:           roleID,
	}, nil
}

func (m *Module) Logout(ctx context.Context, sessionToken string) error {
	return m.store.DeleteSession(ctx, hashToken(sessionToken))
}

func (m *Module) CurrentUser(ctx context.Context, userID string) (*response.User, error) {
	return m.store.GetUserByID(ctx, userID)
}

func (m *Module) GetPasskeys(ctx context.Context, userID string) ([]response.Passkey, error) {
	return m.store.GetPasskeys(ctx, userID)
}

func (m *Module) ListSessions(ctx context.Context, userID string) ([]response.UserSession, error) {
	return m.store.ListUserSessions(ctx, userID)
}

func (m *Module) RevokeSession(ctx context.Context, userID, sessionID string) error {
	return m.store.RevokeUserSession(ctx, userID, sessionID)
}

func (m *Module) RevokeAllSessions(ctx context.Context, userID, currentSessionToken string) error {
	exceptHash := ""
	if currentSessionToken != "" {
		exceptHash = hashToken(currentSessionToken)
	}
	return m.store.RevokeAllUserSessions(ctx, userID, exceptHash)
}

func hashToken(sessionToken string) string {
	hasher := sha256.New()
	hasher.Write([]byte(sessionToken))
	return hex.EncodeToString(hasher.Sum(nil))
}
