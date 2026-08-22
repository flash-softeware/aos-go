package initiator

import (
	"context"
	"net/http"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

// PluginContext exposes runtime dependencies to plugins during registration.
type PluginContext struct {
	Store  storage.Storage
	Cache  storage.CacheRepository
	Events *events.Bus
	Auth   AuthConfig
}

// Plugin is an optional bolt-on (audit, rate limiting, webhooks, …).
type Plugin interface {
	Name() string
	Register(ctx context.Context, pc *PluginContext) error
}

// MiddlewarePlugin optionally wraps the SDK HTTP handler after registration.
type MiddlewarePlugin interface {
	Middleware(next http.Handler) http.Handler
}
