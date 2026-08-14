package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/auth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
)

type Auth struct {
	auth *auth.Module
}

func NewAuth(authModule *auth.Module) *Auth {
	return &Auth{auth: authModule}
}

func (m *Auth) extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if cookie, err := r.Cookie("aos_session"); err == nil {
		return cookie.Value
	}
	return ""
}

func (m *Auth) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			response.SendErrorResponse(w, errors.ErrUnauthorized)
			return
		}

		sess, err := m.auth.ValidateSessionFull(r.Context(), token)
		if err != nil {
			response.SendErrorResponse(w, errors.ErrUnauthorized)
			return
		}

		ctx := identity.WithSession(r.Context(), identity.Session{
			UserID:   sess.UserID,
			TenantID: sess.TenantID,
			OrgID:    sess.OrgID,
			RoleID:   sess.RoleID,
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Auth) OptionalSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		sess, err := m.auth.ValidateSessionFull(r.Context(), token)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := identity.WithSession(r.Context(), identity.Session{
			UserID:   sess.UserID,
			TenantID: sess.TenantID,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CanFunc evaluates authorization for middleware.
type CanFunc func(ctx context.Context, userID, resourceID, permission, tenantID string) (bool, error)

func RequirePermission(can CanFunc, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userID := identity.UserIDFromContext(ctx)
			if userID == "" {
				response.SendErrorResponse(w, errors.ErrUnauthorized)
				return
			}

			resourceID := r.URL.Query().Get("resourceId")
			if resourceID == "" {
				resourceID = identity.OrgIDFromContext(ctx)
			}
			if resourceID == "" {
				resourceID = identity.TenantIDFromContext(ctx)
			}
			if resourceID == "" {
				response.SendErrorResponse(w, errors.ErrBadRequest)
				return
			}

			allowed, err := can(ctx, userID, resourceID, permission, identity.TenantIDFromContext(ctx))
			if err != nil || !allowed {
				response.SendErrorResponse(w, errors.ErrForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
