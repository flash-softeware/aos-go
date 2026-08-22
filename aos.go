package aos

import (
	"context"
	"net/http"

	"github.com/Esubalew-Sintie/aos-auth-go/initiator"
)

// Config exposes the required setup payload for the AOS SDK.
type Config = initiator.Config

type OrganizationConfig = initiator.OrganizationConfig

type AuthConfig = initiator.AuthConfig
type MFAConfig = initiator.MFAConfig
type TOTPConfig = initiator.TOTPConfig
type PasskeyConfig = initiator.PasskeyConfig
type OAuthProviderConfig = initiator.OAuthProviderConfig

// Bool returns a pointer to v for optional bool config fields such as Auth.Password.
func Bool(v bool) *bool {
	return initiator.Bool(v)
}

// AOS is the root embedded identity SDK instance.
type AOS struct {
	app *initiator.Initiator
}

// New initializes the AOS embedded SDK.
func New(ctx context.Context, cfg Config) (*AOS, error) {
	app, err := initiator.Init(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &AOS{app: app}, nil
}

// Handlers exposes individual HTTP handlers for custom route mounting.
func (a *AOS) Handlers() *HandlersAPI {
	return &HandlersAPI{a: a}
}

// Handler mounts all default /v1/* routes (convenience for dev and quick start).
// For custom URLs or selective exposure, use Handlers() and mount handlers yourself.
func (a *AOS) Handler() http.Handler {
	return a.app.HTTPHandler
}

// Router is deprecated; use Handler().
func (a *AOS) Router() http.Handler {
	return a.Handler()
}

// Migrate creates identity tables in the configured database.
func (a *AOS) Migrate(ctx context.Context) error {
	return a.app.Migrate(ctx)
}
