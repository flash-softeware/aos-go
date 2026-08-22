package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
)

const encryptedPrefix = "enc:v1:"

// SecretBox encrypts reversible secrets (e.g. TOTP shared secrets) with AES-256-GCM.
type SecretBox struct {
	key []byte
}

// NewSecretBox builds a box from a 32-byte key (hex, base64, or raw string).
func NewSecretBox(keyMaterial string) (*SecretBox, error) {
	key, err := parseKey(keyMaterial)
	if err != nil {
		return nil, err
	}
	return &SecretBox{key: key}, nil
}

func parseKey(material string) ([]byte, error) {
	if material == "" {
		return nil, aoserrors.ErrEncryptionKeyEmpty
	}
	if len(material) == 64 {
		if key, err := hex.DecodeString(material); err == nil && len(key) == 32 {
			return key, nil
		}
	}
	if key, err := base64.StdEncoding.DecodeString(material); err == nil && len(key) == 32 {
		return key, nil
	}
	if len(material) == 32 {
		return []byte(material), nil
	}
	return nil, aoserrors.ErrEncryptionKeyInvalid
}

// Encrypt stores plaintext as enc:v1:<base64(nonce|ciphertext)>.
func (s *SecretBox) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", aoserrors.ErrPlaintextEmpty
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encryptedPrefix + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt reverses Encrypt. Legacy plaintext secrets (no enc:v1: prefix) pass through.
func (s *SecretBox) Decrypt(stored string) (string, error) {
	if stored == "" {
		return "", aoserrors.ErrSecretEmpty
	}
	if !strings.HasPrefix(stored, encryptedPrefix) {
		return stored, nil
	}

	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, encryptedPrefix))
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return "", aoserrors.ErrCiphertextInvalid
	}

	nonce, ciphertext := payload[:nonceSize], payload[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plaintext), nil
}
