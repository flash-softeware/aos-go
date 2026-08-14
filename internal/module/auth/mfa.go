package auth

import (
	"context"
	"errors"
	"time"

	"github.com/aos/sdk-go/internal/platform/totp"
	"github.com/google/uuid"
)

type MfaStatus struct {
	Enabled  bool `json:"enabled"`
	Verified bool `json:"verified"`
}

func (m *Module) GetMfaStatus(ctx context.Context, userID string) (*MfaStatus, error) {
	enabled, verified, err := m.store.GetMfaStatus(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &MfaStatus{Enabled: enabled, Verified: verified}, nil
}

func (m *Module) MfaEnrollStart(ctx context.Context, userID, email string) (map[string]string, error) {
	secret := totp.GenerateSecret(20)
	if err := m.store.UpsertMfaSecret(ctx, userID, secret); err != nil {
		return nil, err
	}
	return map[string]string{
		"secret":  secret,
		"otpauth": totp.KeyURI(email, "AOS IDaaS", secret),
	}, nil
}

func (m *Module) MfaEnrollVerify(ctx context.Context, userID, code string) (map[string]interface{}, error) {
	secret, err := m.store.GetMfaSecret(ctx, userID)
	if err != nil || secret == "" {
		return nil, errors.New("MFA enrollment not started")
	}
	if !totp.VerifyTOTP(secret, code, 1) {
		return nil, errors.New("Invalid verification code")
	}
	recoveryCodes := totp.RandomRecoveryCodes(8)
	if err := m.store.EnableMfa(ctx, userID, recoveryCodes); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"enabled":       true,
		"recoveryCodes": recoveryCodes,
	}, nil
}

func (m *Module) MfaDisable(ctx context.Context, userID, code string) error {
	secret, recoveryCodes, err := m.store.GetMfaWithRecovery(ctx, userID)
	if err != nil || secret == "" {
		return errors.New("MFA is not enabled")
	}

	validTotp := totp.VerifyTOTP(secret, code, 1)
	upper := stringsToUpper(code)
	validRecovery := false
	for _, rc := range recoveryCodes {
		if rc == upper {
			validRecovery = true
			recoveryCodes = removeCode(recoveryCodes, rc)
			break
		}
	}
	if !validTotp && !validRecovery {
		return errors.New("Invalid code")
	}
	if validRecovery {
		if err := m.store.UpdateMfaRecoveryCodes(ctx, userID, recoveryCodes); err != nil {
			return err
		}
	}
	return m.store.DisableMfa(ctx, userID)
}

func (m *Module) MfaVerifyLogin(ctx context.Context, mfaToken, code string) (map[string]string, error) {
	tokenHash := hashToken(mfaToken)
	userID, err := m.store.ConsumeMfaChallenge(ctx, tokenHash)
	if err != nil || userID == "" {
		return nil, errors.New("Invalid or expired MFA challenge")
	}

	secret, recoveryCodes, err := m.store.GetMfaWithRecovery(ctx, userID)
	if err != nil || secret == "" {
		return nil, errors.New("MFA not configured")
	}

	validTotp := totp.VerifyTOTP(secret, code, 1)
	upper := stringsToUpper(code)
	validRecovery := false
	for _, rc := range recoveryCodes {
		if rc == upper {
			validRecovery = true
			recoveryCodes = removeCode(recoveryCodes, rc)
			break
		}
	}
	if !validTotp && !validRecovery {
		return nil, errors.New("Invalid MFA code")
	}
	if validRecovery {
		_ = m.store.UpdateMfaRecoveryCodes(ctx, userID, recoveryCodes)
	}

	sessionToken, err := m.createSession(ctx, userID)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"session_token": sessionToken,
		"user_id":       userID,
	}, nil
}

func (m *Module) CreateMfaLoginChallenge(ctx context.Context, userID string) (string, error) {
	token := uuid.New().String() + uuid.New().String()
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(5 * time.Minute)
	if err := m.store.InsertMfaChallenge(ctx, userID, tokenHash, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}

func stringsToUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func removeCode(codes []string, target string) []string {
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		if c != target {
			out = append(out, c)
		}
	}
	return out
}
