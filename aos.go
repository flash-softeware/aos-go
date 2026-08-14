package aos

import (
	"context"
	"net/http"

	"github.com/aos/sdk-go/initiator"
)

// Config exposes the required setup payload for the AOS SDK.
type Config = initiator.Config

// AOS is the root embedded identity SDK instance.
type AOS struct {
	App *initiator.Initiator
}

// New initializes the AOS embedded SDK.
func New(ctx context.Context, cfg Config) (*AOS, error) {
	app, err := initiator.Init(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &AOS{App: app}, nil
}

// Router returns the built-in AOS HTTP routes (auth, admin, IAM).
// Mount under /aos or any prefix in the customer application.
func (a *AOS) Router() http.Handler {
	return a.App.HTTPHandler
}

// Migrate creates identity tables in the configured database.
func (a *AOS) Migrate(ctx context.Context) error {
	return a.App.Migrate(ctx)
}
