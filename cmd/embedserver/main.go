// embedserver demonstrates mounting individual AOS handlers on custom URLs.
//
// The host application owns routing; AOS only provides handler functions.
//
// Usage:
//
//	export DATABASE_URL=postgres://...
//	go run ./cmd/embedserver
//
// Route wiring is in routes.go — copy into your app or use the CLI scaffold.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	aos "github.com/Esubalew-Sintie/aos-auth-go"
	"github.com/go-chi/chi/v5"
)

func main() {
	ctx := context.Background()

	cfg := aos.Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		Organization: &aos.OrganizationConfig{
			Enabled: true,
		},
	}
	if key := os.Getenv("MFA_ENCRYPTION_KEY"); key != "" {
		cfg.Auth = aos.AuthConfig{
			MFA: &aos.MFAConfig{
				EncryptionKey: key,
			},
		}
	}

	sdk, err := aos.New(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := sdk.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/health", sdk.Handlers().Health)
	mountAOSRoutes(r, sdk)

	addr := envOr("HTTP_ADDR", ":8080")
	log.Printf("listening on %s (host-owned routes in routes.go)", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
