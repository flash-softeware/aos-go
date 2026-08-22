package aos

import "github.com/Esubalew-Sintie/aos-auth-go/initiator"

type AuthConfig = initiator.AuthConfig
type OAuthProviderConfig = initiator.OAuthProviderConfig
type PasskeyConfig = initiator.PasskeyConfig
type MFAConfig = initiator.MFAConfig
type TOTPConfig = initiator.TOTPConfig

// Bool returns a pointer to v for optional bool config fields such as Auth.Password.
func Bool(v bool) *bool {
	return initiator.Bool(v)
}
