package aos

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Middleware verifies the session token on each request and puts the
// claims in its context (see ClaimsFrom). A request without a valid token
// gets 401. It works with net/http, chi and anything that takes
// func(http.Handler) http.Handler.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := c.VerifyToken(r.Context(), TokenFromRequest(r))
		if err != nil {
			status := http.StatusUnauthorized
			if !errors.Is(err, ErrInvalidToken) {
				status = http.StatusServiceUnavailable
			}
			writeError(w, status, "unauthenticated", "sign in to continue")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

// Optional is Middleware that lets requests without a token through,
// with no claims.
func (c *Client) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := TokenFromRequest(r); token != "" {
			if claims, err := c.VerifyToken(r.Context(), token); err == nil {
				r = r.WithContext(WithClaims(r.Context(), claims))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ResourceFunc names the resource a request is about, such as the invoice
// in its path.
type ResourceFunc func(r *http.Request) Resource

// Root is the top of the tenant's tree: a permission held anywhere above
// counts.
func Root(*http.Request) Resource { return Resource{Type: "tenant", ID: "root"} }

// ActiveOrganization is the organization the person is working in.
func ActiveOrganization(r *http.Request) Resource {
	if c := ClaimsFrom(r.Context()); c != nil && c.Organization != "" {
		return Resource{Type: "organization", ID: c.Organization}
	}
	return Root(r)
}

// RequirePermission answers 403 unless the signed-in person holds the
// permission on the resource. Put it after Middleware.
func (c *Client) RequirePermission(permission string, resource ResourceFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFrom(r.Context())
			if claims == nil {
				writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
				return
			}
			res, err := c.Can(r.Context(), CanRequest{PrincipalID: claims.UserID, Permission: permission, Resource: resource(r), SessionID: claims.SessionID})
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "permission_check_failed", "the permission could not be checked")
				return
			}
			if !res.Allowed {
				writeError(w, http.StatusForbidden, res.Reason, "you may not do this")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "error": map[string]string{"code": code, "message": message}})
}

// CanHandler answers the frontend's <Protect> questions (see
// @aos-auth/react): POST {"permissions": [...], "resource": {"type", "id"}}
// with the session token → {"results": {"permission": true|false}}.
// Without a resource, the active organization (or the root) is asked
// about. Mount it at /api/aos/can.
func (c *Client) CanHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		claims, err := c.VerifyToken(r.Context(), TokenFromRequest(r))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		}
		var body struct {
			Permissions []string  `json:"permissions"`
			Resource    *Resource `json:"resource"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body)
		if len(body.Permissions) > 100 {
			body.Permissions = body.Permissions[:100]
		}
		res := ActiveOrganization(r.WithContext(WithClaims(r.Context(), claims)))
		if body.Resource != nil && body.Resource.Type != "" && body.Resource.ID != "" {
			res = *body.Resource
		}
		results := map[string]bool{}
		if len(body.Permissions) > 0 {
			checks := make([]CanRequest, len(body.Permissions))
			for i, p := range body.Permissions {
				checks[i] = CanRequest{PrincipalID: claims.UserID, Permission: p, Resource: res, SessionID: claims.SessionID}
			}
			answers, err := c.CanBatch(r.Context(), checks)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "permission_check_failed", "the permission could not be checked")
				return
			}
			for i, p := range body.Permissions {
				results[p] = i < len(answers) && answers[i].Allowed
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
}
