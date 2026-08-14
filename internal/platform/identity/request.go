package identity

import "net/http"

// SessionFromRequest returns user, tenant, and org from the authenticated request context.
func SessionFromRequest(r *http.Request) Session {
	return SessionFromContext(r.Context())
}
