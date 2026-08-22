package initiator

import "testing"

func TestNormalizeConfigDefaultsPassword(t *testing.T) {
	cfg := Config{}
	normalizeConfig(&cfg)
	if cfg.Auth.Password == nil || !*cfg.Auth.Password {
		t.Fatal("expected password enabled by default")
	}
}

func TestNormalizeConfigExplicitPasswordDisabled(t *testing.T) {
	cfg := Config{
		Auth: AuthConfig{
			Password: Bool(false),
			OAuth: []OAuthProviderConfig{
				{Name: "google", ClientID: "id", ClientSecret: "secret"},
			},
		},
	}
	normalizeConfig(&cfg)
	if cfg.Auth.PasswordEnabled() {
		t.Fatal("expected password to stay disabled")
	}
}

func TestNormalizeConfigLegacyMfaEncryptionKey(t *testing.T) {
	cfg := Config{
		Auth: AuthConfig{
			MfaEncryptionKey: "0123456789abcdef0123456789abcdef",
		},
	}
	normalizeConfig(&cfg)
	if cfg.Auth.MFA == nil {
		t.Fatal("expected legacy encryption key to enable MFA config")
	}
	if cfg.Auth.MFA.EncryptionKey != cfg.Auth.MfaEncryptionKey {
		t.Fatalf("expected encryption key %q, got %q", cfg.Auth.MfaEncryptionKey, cfg.Auth.MFA.EncryptionKey)
	}
	if cfg.Auth.MFA.TOTP.Issuer != "AOS IDaaS" {
		t.Fatalf("expected default issuer, got %q", cfg.Auth.MFA.TOTP.Issuer)
	}
	if cfg.Auth.MFA.TOTP.RecoveryCodeCount != 8 {
		t.Fatalf("expected default recovery count 8, got %d", cfg.Auth.MFA.TOTP.RecoveryCodeCount)
	}
}

func TestNormalizeConfigOrganizationAutoSetActive(t *testing.T) {
	cfg := Config{
		Organization: &OrganizationConfig{Enabled: true},
	}
	normalizeConfig(&cfg)
	if cfg.Organization.AutoSetActiveOnLogin == nil || !*cfg.Organization.AutoSetActiveOnLogin {
		t.Fatal("expected AutoSetActiveOnLogin true when org enabled")
	}
	if !cfg.Organization.AutoSetActiveOnLoginEnabled() {
		t.Fatal("expected AutoSetActiveOnLoginEnabled true")
	}
}

func TestNormalizeConfigOrganizationDisabled(t *testing.T) {
	cfg := Config{
		Organization: &OrganizationConfig{Enabled: false},
	}
	normalizeConfig(&cfg)
	if cfg.Organization.AutoSetActiveOnLogin != nil {
		t.Fatal("expected AutoSetActiveOnLogin unset when org disabled")
	}
}

func TestNormalizeConfigAdminPermissionDefault(t *testing.T) {
	cfg := Config{}
	normalizeConfig(&cfg)
	if cfg.AdminPermission != "user.read" {
		t.Fatalf("expected default admin permission user.read, got %q", cfg.AdminPermission)
	}
}

func TestNormalizeConfigMfaTOTPDefaults(t *testing.T) {
	cfg := Config{
		Auth: AuthConfig{
			MFA: &MFAConfig{
				EncryptionKey: "0123456789abcdef0123456789abcdef",
				TOTP: &TOTPConfig{
					Issuer:            "My App",
					RecoveryCodeCount: 10,
				},
			},
		},
	}
	normalizeConfig(&cfg)
	if cfg.Auth.MFA.TOTP.Issuer != "My App" {
		t.Fatalf("expected custom issuer, got %q", cfg.Auth.MFA.TOTP.Issuer)
	}
	if cfg.Auth.MFA.TOTP.RecoveryCodeCount != 10 {
		t.Fatalf("expected recovery count 10, got %d", cfg.Auth.MFA.TOTP.RecoveryCodeCount)
	}
}
