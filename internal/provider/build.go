package provider

import (
	"strings"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/oauth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/password"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

// AuthOptions mirrors initiator.AuthConfig for provider wiring.
type AuthOptions struct {
	Password bool
	OAuth    []OAuthOption
}

type OAuthOption struct {
	Name         string
	ClientID     string
	ClientSecret string
}

// Registry holds enabled auth providers.
type Registry struct {
	Password *password.Provider
	OAuth    *oauth.Provider
}

// Build constructs providers from auth options.
func Build(store storage.Storage, auth AuthOptions) *Registry {
	reg := &Registry{}

	if auth.Password {
		reg.Password = password.New(store)
	}

	if len(auth.OAuth) > 0 {
		creds := make(map[string]oauth.Credentials, len(auth.OAuth))
		for _, p := range auth.OAuth {
			name := strings.ToUpper(strings.TrimSpace(p.Name))
			creds[name] = oauth.Credentials{
				ClientID:     p.ClientID,
				ClientSecret: p.ClientSecret,
			}
		}
		reg.OAuth = oauth.New(store, creds)
	}

	return reg
}
