package aos

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Claims is what a verified session token says.
type Claims struct {
	// UserID is the signed-in person (the "sub" claim).
	UserID    string `json:"sub"`
	SessionID string `json:"sid"`
	TenantID  string `json:"tid"`
	// Organization is the active organization's id in the application,
	// and OrganizationID its resource id in the engine. Both are empty
	// when none is active.
	Organization   string `json:"org"`
	OrganizationID string `json:"org_id"`
	// AssuranceLevel: 0 nothing verified, 1 email, 2 phone.
	AssuranceLevel int    `json:"aal"`
	Type           string `json:"typ"`
	IssuedAt       int64  `json:"iat"`
	ExpiresAt      int64  `json:"exp"`
}

// ErrInvalidToken is returned for a token that is malformed, signed by
// another tenant, tampered with or expired.
var ErrInvalidToken = errors.New("aos: invalid or expired token")

type keyEntry struct{ key ed25519.PublicKey }

var b64 = base64.RawURLEncoding

// VerifyToken checks a session token locally: the signature against the
// tenant's published keys, and the expiry. It calls the engine only to
// fetch the keys, at most once per KeysTTL or when an unknown key appears.
func (c *Client) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerJSON, &header) != nil || header.Alg != "EdDSA" {
		return nil, ErrInvalidToken
	}
	key, err := c.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, ErrInvalidToken
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrInvalidToken
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if json.Unmarshal(payload, &claims) != nil || claims.UserID == "" {
		return nil, ErrInvalidToken
	}
	// A minute of clock skew is allowed.
	if c.now().Unix() > claims.ExpiresAt+60 {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

func (c *Client) key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	c.mu.Lock()
	entry, ok := c.keys[kid]
	fresh := c.now().Sub(c.keysAt) < c.cfg.KeysTTL
	// An unknown key may be a new one: refetch, but not more than every 10 s.
	mayFetch := !fresh || (!ok && c.now().Sub(c.lastFetch) > 10*time.Second)
	c.mu.Unlock()
	if ok && fresh {
		return entry.key, nil
	}
	if !mayFetch {
		if ok {
			return entry.key, nil
		}
		return nil, nil
	}
	keys, err := c.fetchKeys(ctx)
	if err != nil {
		if ok {
			return entry.key, nil // keep using a known key while the engine is unreachable
		}
		return nil, err
	}
	c.mu.Lock()
	c.keys, c.keysAt, c.lastFetch = keys, c.now(), c.now()
	entry, ok = c.keys[kid]
	c.mu.Unlock()
	if !ok {
		return nil, nil
	}
	return entry.key, nil
}

func (c *Client) fetchKeys(ctx context.Context) (map[string]keyEntry, error) {
	if c.cfg.PublishableKey == "" {
		return nil, errors.New("aos: verifying tokens needs Config.PublishableKey")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-AOS-Publishable-Key", c.cfg.PublishableKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Code: "jwks_unavailable", Message: "the engine did not return its public keys"}
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	out := map[string]keyEntry{}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		raw, err := b64.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		out[k.Kid] = keyEntry{key: ed25519.PublicKey(raw)}
	}
	return out, nil
}

// TokenFromRequest reads the token from "Authorization: Bearer ...".
func TokenFromRequest(r *http.Request) string {
	t, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(t)
}

type claimsKey struct{}

// WithClaims puts claims in a context.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// ClaimsFrom returns the claims Middleware put in the request's context,
// or nil.
func ClaimsFrom(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey{}).(*Claims)
	return c
}
