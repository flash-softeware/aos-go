package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

type Service struct {
	w *webauthn.WebAuthn
}

type User struct {
	ID          string
	Email       string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u User) WebAuthnID() []byte                          { return []byte(u.ID) }
func (u User) WebAuthnName() string                        { return u.Email }
func (u User) WebAuthnDisplayName() string                 { return u.DisplayName }
func (u User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func New(cfg Config) (*Service, error) {
	if cfg.RPID == "" {
		cfg.RPID = "localhost"
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "AOS Identity Service"
	}
	if len(cfg.RPOrigins) == 0 {
		cfg.RPOrigins = defaultLocalhostOrigins()
	}

	w, err := webauthn.New(&webauthn.Config{
		RPID:                 cfg.RPID,
		RPDisplayName:        cfg.RPDisplayName,
		RPOrigins:            cfg.RPOrigins,
		EncodeUserIDAsString: true,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}

	return &Service{w: w}, nil
}

func defaultLocalhostOrigins() []string {
	hosts := []string{"localhost", "127.0.0.1"}
	ranges := [][2]int{{3000, 3010}, {5173, 5200}}
	origins := make([]string, 0, len(hosts)*len(ranges)*30)

	for _, host := range hosts {
		for _, r := range ranges {
			for port := r[0]; port <= r[1]; port++ {
				origins = append(origins, fmt.Sprintf("http://%s:%d", host, port))
			}
		}
	}

	return origins
}

func ParseOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		if origin := strings.TrimSpace(part); origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}

func (s *Service) BeginRegistration(user User) (*protocol.PublicKeyCredentialCreationOptions, *webauthn.SessionData, error) {
	opts := []webauthn.RegistrationOption{}
	if len(user.Credentials) > 0 {
		opts = append(opts, webauthn.WithExclusions(webauthn.Credentials(user.Credentials).CredentialDescriptors()))
	}

	creation, session, err := s.w.BeginRegistration(user, opts...)
	if err != nil {
		return nil, nil, err
	}

	return &creation.Response, session, nil
}

func (s *Service) FinishRegistration(user User, session webauthn.SessionData, body []byte) (*webauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return s.w.CreateCredential(user, session, parsed)
}

func (s *Service) BeginLogin(user User) (*protocol.PublicKeyCredentialRequestOptions, *webauthn.SessionData, error) {
	assertion, session, err := s.w.BeginLogin(user)
	if err != nil {
		return nil, nil, err
	}

	return &assertion.Response, session, nil
}

func (s *Service) FinishLogin(user User, session webauthn.SessionData, body []byte) (*webauthn.Credential, error) {
	body = normalizeAssertionUserHandle(body)

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return s.w.ValidateLogin(user, session, parsed)
}

// normalizeAssertionUserHandle converts plain-text userHandle values emitted by
// @simplewebauthn/browser (when user.id was registered as a UTF-8 string) into the
// base64url form expected by go-webauthn's URLEncodedBase64 parser.
func normalizeAssertionUserHandle(body []byte) []byte {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}

	response, ok := payload["response"].(map[string]any)
	if !ok {
		return body
	}

	userHandle, ok := response["userHandle"].(string)
	if !ok || userHandle == "" {
		return body
	}

	// Plain UUID / string handles from simplewebauthn include punctuation such as '-'.
	if strings.ContainsAny(userHandle, "-:") {
		response["userHandle"] = base64.RawURLEncoding.EncodeToString([]byte(userHandle))
		out, err := json.Marshal(payload)
		if err != nil {
			return body
		}
		return out
	}

	return body
}

func CredentialFromStorage(credentialID, publicKey string, signCount int64, backupEligible, backedUp bool) (webauthn.Credential, error) {
	id, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode credential id: %w", err)
	}

	pk, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode public key: %w", err)
	}

	return webauthn.Credential{
		ID:        id,
		PublicKey: pk,
		Flags: webauthn.CredentialFlags{
			BackupEligible: backupEligible,
			BackupState:    backedUp,
		},
		Authenticator: webauthn.Authenticator{
			SignCount: uint32(signCount),
		},
	}, nil
}

func CredentialToStorage(c *webauthn.Credential) (credentialID, publicKey string, signCount int64) {
	return base64.RawURLEncoding.EncodeToString(c.ID),
		base64.RawURLEncoding.EncodeToString(c.PublicKey),
		int64(c.Authenticator.SignCount)
}
