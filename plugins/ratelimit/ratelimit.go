package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/initiator"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

const defaultMaxAttempts = 10

var authRoutePrefixes = []string{
	"/v1/auth/login",
	"/v1/auth/register",
	"/v1/auth/mfa/verify",
	"/v1/auth/passkeys/authenticate",
	"/v1/auth/password/forgot",
	"/v1/auth/password/reset",
}

// Plugin limits brute-force attempts on public auth routes using Redis.
type Plugin struct {
	cache       storage.CacheRepository
	maxAttempts int
	window      time.Duration
}

// New creates a rate-limit plugin. Pass cfg.RedisAddr from aos.Config.
func New(_ string) *Plugin {
	return &Plugin{
		maxAttempts: defaultMaxAttempts,
		window:      15 * time.Minute,
	}
}

func (p *Plugin) Name() string {
	return "ratelimit"
}

func (p *Plugin) Register(_ context.Context, pc *initiator.PluginContext) error {
	if pc.Cache == nil {
		return fmt.Errorf("ratelimit plugin requires Redis (set Config.RedisAddr)")
	}
	p.cache = pc.Cache
	return nil
}

func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !isAuthRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		key := fmt.Sprintf("aos:ratelimit:%s:%s", clientIP(r), r.URL.Path)
		count, err := p.cache.Get(r.Context(), key)
		if err == nil {
			if n, _ := strconv.Atoi(count); n >= p.maxAttempts {
				response.SendErrorResponse(w, errors.ErrTooManyRequests)
				return
			}
		}

		next.ServeHTTP(w, r)

		n, _ := strconv.Atoi(count)
		_ = p.cache.Set(r.Context(), key, n+1, p.window)
	})
}

func isAuthRoute(path string) bool {
	for _, prefix := range authRoutePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
