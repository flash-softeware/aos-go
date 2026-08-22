package initiator

import "github.com/Esubalew-Sintie/aos-auth-go/internal/storage"

// Config is the SDK wiring payload (see ARCHITECTURE.md v0.2 contract).
type Config struct {
	DatabaseURL string
	Storage     storage.Storage // optional; overrides DatabaseURL

	TenantType   string
	RedisAddr    string
	EventsStrict bool

	// AdminPermission is the permission code required for default admin routes (default: user.read).
	AdminPermission string

	Auth AuthConfig

	// Organization toggles the org layer (memberships, active org, org-scoped RBAC).
	Organization *OrganizationConfig

	// Deprecated: prefer Auth.Passkey. Kept for backward compatibility.
	WebAuthnRPID      string
	WebAuthnRPOrigins []string

	Plugins []Plugin
}

// AuthConfig selects which authentication methods are enabled and how they are configured.
type AuthConfig struct {
	// Password enables email/password sign-in. nil means enabled by default.
	Password *bool

	// OAuth providers seeded into storage at init (platform scope, empty tenant_id).
	OAuth []OAuthProviderConfig

	// Passkey enables WebAuthn when set. nil means disabled.
	Passkey *PasskeyConfig

	// MFA enables TOTP multi-factor authentication when set. nil means disabled.
	MFA *MFAConfig

	// Deprecated: use MFA.EncryptionKey.
	MfaEncryptionKey string
}

// MFAConfig configures multi-factor authentication.
type MFAConfig struct {
	// EncryptionKey is a 32-byte key (hex, base64, or raw) used to encrypt TOTP secrets at rest.
	EncryptionKey string

	// TOTP holds authenticator-app settings. Defaults are applied when nil.
	TOTP *TOTPConfig
}

// TOTPConfig configures TOTP enrollment and recovery codes.
type TOTPConfig struct {
	// Issuer displayed in authenticator apps.
	Issuer string

	// RecoveryCodeCount is the number of one-time backup codes generated at enrollment.
	RecoveryCodeCount int
}

// OAuthProviderConfig holds OAuth client credentials for a social provider.
type OAuthProviderConfig struct {
	Name         string // e.g. "google", "github"
	ClientID     string
	ClientSecret string
}

// PasskeyConfig configures WebAuthn / passkey authentication.
type PasskeyConfig struct {
	RPID    string
	Origins []string
}

// OrganizationConfig toggles the organization layer for embedded installs.
type OrganizationConfig struct {
	// Enabled turns on organization APIs, memberships, and org-scoped authorization.
	Enabled bool

	// AutoSetActiveOnLogin picks an active organization after login when Enabled.
	// Defaults to true when Enabled is true.
	AutoSetActiveOnLogin *bool
}

// AutoSetActiveOnLoginEnabled reports whether login should set an active org.
func (o OrganizationConfig) AutoSetActiveOnLoginEnabled() bool {
	if o.AutoSetActiveOnLogin != nil {
		return *o.AutoSetActiveOnLogin
	}
	return o.Enabled
}

// Bool returns a pointer to v for optional bool config fields.
func Bool(v bool) *bool {
	return &v
}

// PasswordEnabled reports whether password authentication is enabled.
func (a AuthConfig) PasswordEnabled() bool {
	if a.Password == nil {
		return true
	}
	return *a.Password
}

func normalizeConfig(cfg *Config) {
	if cfg.Auth.Password == nil &&
		len(cfg.Auth.OAuth) == 0 &&
		cfg.Auth.Passkey == nil &&
		cfg.Auth.MFA == nil {
		cfg.Auth.Password = Bool(true)
	}

	if cfg.Auth.MFA == nil && cfg.Auth.MfaEncryptionKey != "" {
		cfg.Auth.MFA = &MFAConfig{EncryptionKey: cfg.Auth.MfaEncryptionKey}
	}
	if cfg.Auth.MFA != nil && cfg.Auth.MFA.EncryptionKey == "" {
		cfg.Auth.MFA.EncryptionKey = cfg.Auth.MfaEncryptionKey
	}

	if cfg.Auth.MFA != nil {
		if cfg.Auth.MFA.TOTP == nil {
			cfg.Auth.MFA.TOTP = &TOTPConfig{}
		}
		if cfg.Auth.MFA.TOTP.Issuer == "" {
			cfg.Auth.MFA.TOTP.Issuer = "AOS IDaaS"
		}
		if cfg.Auth.MFA.TOTP.RecoveryCodeCount <= 0 {
			cfg.Auth.MFA.TOTP.RecoveryCodeCount = 8
		}
	}

	if cfg.Auth.Passkey != nil {
		if cfg.WebAuthnRPID == "" {
			cfg.WebAuthnRPID = cfg.Auth.Passkey.RPID
		}
		if len(cfg.WebAuthnRPOrigins) == 0 {
			cfg.WebAuthnRPOrigins = cfg.Auth.Passkey.Origins
		}
	}

	if cfg.Auth.Passkey == nil && (cfg.WebAuthnRPID != "" || len(cfg.WebAuthnRPOrigins) > 0) {
		cfg.Auth.Passkey = &PasskeyConfig{
			RPID:    cfg.WebAuthnRPID,
			Origins: cfg.WebAuthnRPOrigins,
		}
	}

	if cfg.Organization != nil && cfg.Organization.Enabled && cfg.Organization.AutoSetActiveOnLogin == nil {
		cfg.Organization.AutoSetActiveOnLogin = Bool(true)
	}

	if cfg.AdminPermission == "" {
		cfg.AdminPermission = "user.read"
	}
}
