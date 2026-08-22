package crypto

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashRecoveryCode returns a bcrypt hash of a normalized recovery code.
func HashRecoveryCode(code string) (string, error) {
	normalized := NormalizeRecoveryCode(code)
	if normalized == "" {
		return "", bcrypt.ErrHashTooShort
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(normalized), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// VerifyRecoveryCode checks a user-supplied code against a stored bcrypt hash.
// Legacy plaintext hashes (non-bcrypt) are compared directly for migration.
func VerifyRecoveryCode(code, stored string) bool {
	normalized := NormalizeRecoveryCode(code)
	if normalized == "" || stored == "" {
		return false
	}
	if !strings.HasPrefix(stored, "$2") {
		return NormalizeRecoveryCode(stored) == normalized
	}
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(normalized)) == nil
}

// HashRecoveryCodes bcrypt-hashes each recovery code for storage.
func HashRecoveryCodes(codes []string) ([]string, error) {
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hash, err := HashRecoveryCode(code)
		if err != nil {
			return nil, err
		}
		hashes[i] = hash
	}
	return hashes, nil
}

// NormalizeRecoveryCode uppercases and strips spaces/dashes from a recovery code.
func NormalizeRecoveryCode(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	return normalized
}
