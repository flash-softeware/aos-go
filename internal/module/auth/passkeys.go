package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	webauthnplatform "github.com/Esubalew-Sintie/aos-auth-go/internal/platform/webauthn"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (m *Module) loadWebAuthnUser(ctx context.Context, userID string) (webauthnplatform.User, error) {
	user, err := m.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return webauthnplatform.User{}, errors.New("user not found")
	}

	records, err := m.store.GetPasskeyRecords(ctx, userID)
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

	return m.store.InsertPasskeyChallenge(ctx, userID, string(payload), expiresAt)
}

func (m *Module) loadPasskeySession(ctx context.Context, userID string) (webauthn.SessionData, error) {
	raw, err := m.store.GetPasskeyChallenge(ctx, userID)
	if err != nil {
		return webauthn.SessionData{}, errors.New("challenge expired or not found")
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &session); err != nil {
		_ = m.store.DeletePasskeyChallenge(ctx, userID)
		return webauthn.SessionData{}, errors.New("passkey session expired, please start registration again")
	}

	return session, nil
}

func (m *Module) GenerateRegistrationOptions(ctx context.Context, userID string) (any, error) {
	if m.webauthn == nil {
		return nil, errors.New("webauthn is not configured")
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
		return response.PasskeyVerification{Verified: false}, errors.New("webauthn is not configured")
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

	if err := m.store.InsertPasskey(
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

	_ = m.store.DeletePasskeyChallenge(ctx, userID)
	return response.PasskeyVerification{Verified: true}, nil
}

func (m *Module) GenerateAuthenticationOptions(ctx context.Context, email string) (any, error) {
	if m.webauthn == nil {
		return nil, errors.New("webauthn is not configured")
	}

	userID, err := m.store.GetUserIDByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("no passkeys registered for this account")
	}

	user, err := m.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(user.Credentials) == 0 {
		return nil, errors.New("no passkeys registered for this account")
	}

	options, session, err := m.webauthn.BeginLogin(user)
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
		return nil, errors.New("webauthn is not configured")
	}

	userID, err := m.store.GetUserIDByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("authentication failed")
	}

	user, err := m.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	session, err := m.loadPasskeySession(ctx, userID)
	if err != nil {
		return nil, err
	}

	credential, err := m.webauthn.FinishLogin(user, session, payload)
	if err != nil {
		return nil, err
	}

	credentialID, _, signCount := webauthnplatform.CredentialToStorage(credential)
	if err := m.store.UpdatePasskeySignCount(ctx, userID, credentialID, signCount); err != nil {
		return nil, err
	}

	_ = m.store.DeletePasskeyChallenge(ctx, userID)

	sessionToken, err := m.createSession(ctx, userID)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"session_token": sessionToken,
		"user_id":       userID,
	}, nil
}
