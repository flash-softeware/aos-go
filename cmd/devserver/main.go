// devserver runs AOS with all default /v1/* routes mounted via sdk.Handler().
//
// Usage:
//
//	export DATABASE_URL=postgres://...
//	go run ./cmd/devserver
//
// Optional MFA:
//
//	export MFA_ENCRYPTION_KEY=$(openssl rand -hex 32)
//	go run ./cmd/devserver
//
// For custom URLs and selective route exposure, see cmd/embedserver.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	aos "github.com/Esubalew-Sintie/aos-auth-go"
)

func main() {
	ctx := context.Background()

	cfg := aos.Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		Organization: &aos.OrganizationConfig{
			Enabled: true, // AutoSetActiveOnLogin defaults true when enabled
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

	addr := envOr("HTTP_ADDR", ":8080")
	log.Printf("listening on %s (default /v1/* routes via sdk.Handler())", addr)
	log.Fatal(http.ListenAndServe(addr, sdk.Handler()))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
