package auth

import (
	"context"
	"encoding/json"
	"time"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	webauthnplatform "github.com/Esubalew-Sintie/aos-auth-go/internal/platform/webauthn"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (m *Module) loadWebAuthnUser(ctx context.Context, userID string) (webauthnplatform.User, error) {
	user, err := m.store.Users().GetByID(ctx, userID)
	if err != nil || user == nil {
		return webauthnplatform.User{}, aoserrors.ErrUserNotFound
	}

	records, err := m.store.Passkeys().ListRecords(ctx, userID)
	if err != nil {
		return webauthnplatform.User{}, err
	}

	credentials := make([]webauthn.Credential, 0, len(records))
	for _, record := range records {
		cred, err := webauthnplatform.CredentialFromStorage(
			record.CredentialID,
			record.PublicKey,
			record.SignCount,
			record.BackupEligible,
			record.BackedUp,
		)
		if err != nil {
			continue
		}
		credentials = append(credentials, cred)
	}

	displayName := user.FirstName
	if displayName == "" {
		displayName = user.Email
	}

	return webauthnplatform.User{
		ID:          userID,
		Email:       user.Email,
		DisplayName: displayName,
		Credentials: credentials,
	}, nil
}

func (m *Module) storePasskeySession(ctx context.Context, userID string, session *webauthn.SessionData) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(10 * time.Minute)
	if !session.Expires.IsZero() {
		expiresAt = session.Expires
	}

	return m.store.Passkeys().InsertChallenge(ctx, userID, string(payload), expiresAt)
}

func (m *Module) loadPasskeySession(ctx context.Context, userID string) (webauthn.SessionData, error) {
	raw, err := m.store.Passkeys().GetChallenge(ctx, userID)
	if err != nil {
		return webauthn.SessionData{}, aoserrors.ErrPasskeyChallengeExpired
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &session); err != nil {
		_ = m.store.Passkeys().DeleteChallenge(ctx, userID)
		return webauthn.SessionData{}, aoserrors.ErrPasskeySessionExpired
	}

	return session, nil
}

func (m *Module) GenerateRegistrationOptions(ctx context.Context, userID string) (any, error) {
	if m.webauthn == nil {
		return nil, aoserrors.ErrWebAuthnNotConfigured
	}

	user, err := m.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	options, session, err := m.webauthn.BeginRegistration(user)
	if err != nil {
		return nil, err
	}

	if err := m.storePasskeySession(ctx, userID, session); err != nil {
		return nil, err
	}

	return options, nil
}

func (m *Module) VerifyRegistration(ctx context.Context, userID string, payload []byte) (response.PasskeyVerification, error) {
	if m.webauthn == nil {
		return response.PasskeyVerification{Verified: false}, aoserrors.ErrWebAuthnNotConfigured
	}

	user, err := m.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return response.PasskeyVerification{Verified: false}, err
	}

	session, err := m.loadPasskeySession(ctx, userID)
	if err != nil {
		return response.PasskeyVerification{Verified: false}, err
	}

	credential, err := m.webauthn.FinishRegistration(user, session, payload)
	if err != nil {
		return response.PasskeyVerification{Verified: false}, err
	}

	credentialID, publicKey, signCount := webauthnplatform.CredentialToStorage(credential)
	deviceName := string(credential.Authenticator.Attachment)
	if deviceName == "" {
		deviceName = "Passkey"
	}

	if err := m.store.Passkeys().Insert(
		ctx,
		userID,
		credentialID,
		publicKey,
		signCount,
		deviceName,
		credential.Flags.BackupEligible,
		credential.Flags.BackupState,
	); err != nil {
		return response.PasskeyVerification{Verified: false}, err
	}

	_ = m.store.Passkeys().DeleteChallenge(ctx, userID)
	return response.PasskeyVerification{Verified: true}, nil
}

func (m *Module) GenerateAuthenticationOptions(ctx context.Context, email string) (any, error) {
	if m.webauthn == nil {
		return nil, aoserrors.ErrWebAuthnNotConfigured
	}

	user, err := m.store.Users().GetByEmail(ctx, email)
	if err != nil {
		return nil, aoserrors.ErrNoPasskeysRegistered
	}

	userID := user.ID
	webauthnUser, err := m.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(webauthnUser.Credentials) == 0 {
		return nil, aoserrors.ErrNoPasskeysRegistered
	}

	options, session, err := m.webauthn.BeginLogin(webauthnUser)
	if err != nil {
		return nil, err
	}

	if err := m.storePasskeySession(ctx, userID, session); err != nil {
		return nil, err
	}

	return options, nil
}

func (m *Module) VerifyAuthentication(ctx context.Context, email string, payload []byte) (map[string]string, error) {
	if m.webauthn == nil {
		return nil, aoserrors.ErrWebAuthnNotConfigured
	}

	user, err := m.store.Users().GetByEmail(ctx, email)
	if err != nil {
		return nil, aoserrors.ErrPasskeyAuthenticationFailed
	}
	userID := user.ID

	webauthnUser, err := m.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	session, err := m.loadPasskeySession(ctx, userID)
	if err != nil {
		return nil, err
	}

	credential, err := m.webauthn.FinishLogin(webauthnUser, session, payload)
	if err != nil {
		return nil, err
	}

	credentialID, _, signCount := webauthnplatform.CredentialToStorage(credential)
	if err := m.store.Passkeys().UpdateSignCount(ctx, userID, credentialID, signCount); err != nil {
		return nil, err
	}

	_ = m.store.Passkeys().DeleteChallenge(ctx, userID)

	sessionToken, err := m.createSession(ctx, userID)
	if err != nil {
		return nil, err
	}
	_ = m.autoSetActiveOrganization(ctx, sessionToken, userID)

	return map[string]string{
		"session_token": sessionToken,
		"user_id":       userID,
	}, nil
}
