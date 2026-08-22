package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a cryptographically random Base32 TOTP secret.
func GenerateSecret(length int) (string, error) {
	if length <= 0 {
		length = 20
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random secret: %w", err)
	}
	return base32Encoding.EncodeToString(b), nil
}

// DecodeBase32 decodes a Base32-encoded TOTP secret.
func DecodeBase32(input string) ([]byte, error) {
	input = strings.ToUpper(strings.TrimRight(strings.TrimSpace(input), "="))
	if input == "" {
		return nil, fmt.Errorf("empty base32 secret")
	}
	key, err := base32Encoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("decode base32 secret: %w", err)
	}
	return key, nil
}

func hotp(key []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// GenerateTOTP returns the TOTP code for the given secret and time step.
// When step is 0, the current 30-second window is used.
func GenerateTOTP(secret string, step int64) (string, error) {
	key, err := DecodeBase32(secret)
	if err != nil {
		return "", err
	}
	if step == 0 {
		step = time.Now().Unix() / 30
	}
	if step < 0 {
		return "", fmt.Errorf("invalid totp step: %d", step)
	}
	return hotp(key, uint64(step)), nil
}

// VerifyTOTP checks the token against the secret within ±window 30-second steps.
func VerifyTOTP(secret, token string, window int) bool {
	if window <= 0 {
		window = 1
	}

	normalized := strings.ReplaceAll(strings.TrimSpace(token), " ", "")
	if len(normalized) != 6 {
		return false
	}

	key, err := DecodeBase32(secret)
	if err != nil {
		return false
	}

	step := time.Now().Unix() / 30
	for i := -window; i <= window; i++ {
		candidate := step + int64(i)
		if candidate < 0 {
			continue
		}
		expected := hotp(key, uint64(candidate))
		if hmac.Equal([]byte(expected), []byte(normalized)) {
			return true
		}
	}
	return false
}

// KeyURI builds an otpauth:// URI for authenticator apps.
func KeyURI(account, issuer, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

// RandomRecoveryCodes generates one-time backup codes (formatted XXXX-XXXX-XXXX).
func RandomRecoveryCodes(count int) ([]string, error) {
	if count <= 0 {
		count = 8
	}
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		raw := base32Encoding.EncodeToString(b)
		if len(raw) < 12 {
			codes[i] = strings.ToUpper(raw)
			continue
		}
		codes[i] = strings.ToUpper(raw[:4] + "-" + raw[4:8] + "-" + raw[8:12])
	}
	return codes, nil
}
