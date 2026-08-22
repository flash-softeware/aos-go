package auth

import (
	"context"
	"time"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/crypto"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/totp"
	"github.com/google/uuid"
)

type MfaStatus struct {
	Enabled  bool `json:"enabled"`
	Verified bool `json:"verified"`
}

func (m *Module) GetMfaStatus(ctx context.Context, userID string) (*MfaStatus, error) {
	enabled, verified, err := m.store.Mfa().Status(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &MfaStatus{Enabled: enabled, Verified: verified}, nil
}

func (m *Module) MfaEnrollStart(ctx context.Context, userID, email string) (map[string]string, error) {
	if err := m.requireMfaBox(); err != nil {
		return nil, err
	}
	secret, err := totp.GenerateSecret(20)
	if err != nil {
		return nil, err
	}
	encrypted, err := m.mfaBox.Encrypt(secret)
	if err != nil {
		return nil, err
	}
	if err := m.store.Mfa().UpsertSecret(ctx, userID, encrypted); err != nil {
		return nil, err
	}
	return map[string]string{
		"secret":  secret,
		"otpauth": totp.KeyURI(email, m.mfaOpts.Issuer, secret),
	}, nil
}

func (m *Module) MfaEnrollVerify(ctx context.Context, userID, code string) (map[string]interface{}, error) {
	if err := m.requireMfaBox(); err != nil {
		return nil, err
	}
	secret, err := m.getDecryptedSecret(ctx, userID)
	if err != nil || secret == "" {
		return nil, aoserrors.ErrMfaEnrollmentNotStarted
	}
	if !totp.VerifyTOTP(secret, code, 1) {
		return nil, aoserrors.ErrMfaInvalidVerificationCode
	}
	recoveryCodes, err := totp.RandomRecoveryCodes(m.mfaOpts.RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	hashedCodes, err := crypto.HashRecoveryCodes(recoveryCodes)
	if err != nil {
		return nil, err
	}
	if err := m.store.Mfa().Enable(ctx, userID, hashedCodes); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"enabled":       true,
		"recoveryCodes": recoveryCodes,
	}, nil
}

func (m *Module) MfaDisable(ctx context.Context, userID, code string) error {
	if err := m.requireMfaBox(); err != nil {
		return err
	}
	secret, storedHashes, err := m.getDecryptedSecretWithRecovery(ctx, userID)
	if err != nil || secret == "" {
		return aoserrors.ErrMfaNotEnabled
	}

	validTotp := totp.VerifyTOTP(secret, code, 1)
	remaining, validRecovery := verifyAndConsumeRecovery(code, storedHashes)
	if !validTotp && !validRecovery {
		return aoserrors.ErrMfaInvalidCode
	}
	if validRecovery {
		if err := m.store.Mfa().UpdateRecoveryCodes(ctx, userID, remaining); err != nil {
			return err
		}
	}
	return m.store.Mfa().Disable(ctx, userID)
}

func (m *Module) MfaVerifyLogin(ctx context.Context, mfaToken, code string) (map[string]string, error) {
	if err := m.requireMfaBox(); err != nil {
		return nil, err
	}
	tokenHash := hashToken(mfaToken)
	userID, err := m.store.Mfa().ConsumeChallenge(ctx, tokenHash)
	if err != nil || userID == "" {
		return nil, aoserrors.ErrMfaChallengeInvalid
	}

	secret, storedHashes, err := m.getDecryptedSecretWithRecovery(ctx, userID)
	if err != nil || secret == "" {
		return nil, aoserrors.ErrMfaNotConfigured
	}

	validTotp := totp.VerifyTOTP(secret, code, 1)
	remaining, validRecovery := verifyAndConsumeRecovery(code, storedHashes)
	if !validTotp && !validRecovery {
		return nil, aoserrors.ErrMfaInvalidCode
	}
	if validRecovery {
		_ = m.store.Mfa().UpdateRecoveryCodes(ctx, userID, remaining)
	}

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

func (m *Module) CreateMfaLoginChallenge(ctx context.Context, userID string) (string, error) {
	token := uuid.New().String() + uuid.New().String()
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(5 * time.Minute)
	if err := m.store.Mfa().InsertChallenge(ctx, userID, tokenHash, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}

func (m *Module) requireMfaBox() error {
	if m.mfaBox == nil {
		return aoserrors.ErrMfaNotConfigured
	}
	return nil
}

func (m *Module) getDecryptedSecret(ctx context.Context, userID string) (string, error) {
	if err := m.requireMfaBox(); err != nil {
		return "", err
	}
	stored, err := m.store.Mfa().GetSecret(ctx, userID)
	if err != nil {
		return "", err
	}
	return m.mfaBox.Decrypt(stored)
}

func (m *Module) getDecryptedSecretWithRecovery(ctx context.Context, userID string) (string, []string, error) {
	if err := m.requireMfaBox(); err != nil {
		return "", nil, err
	}
	storedSecret, storedHashes, err := m.store.Mfa().GetWithRecovery(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	secret, err := m.mfaBox.Decrypt(storedSecret)
	if err != nil {
		return "", nil, err
	}
	return secret, storedHashes, nil
}

func verifyAndConsumeRecovery(code string, stored []string) (remaining []string, ok bool) {
	for i, hash := range stored {
		if crypto.VerifyRecoveryCode(code, hash) {
			return removeAt(stored, i), true
		}
	}
	return stored, false
}

func removeAt(items []string, index int) []string {
	out := make([]string, 0, len(items)-1)
	out = append(out, items[:index]...)
	out = append(out, items[index+1:]...)
	return out
}
