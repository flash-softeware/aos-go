package aos

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEngine serves the keys and a /v1/can that allows only "invoice.read".
type fakeEngine struct {
	srv       *httptest.Server
	priv      ed25519.PrivateKey
	kid       string
	jwksCalls atomic.Int32
}

func newFake(t *testing.T) *fakeEngine {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeEngine{priv: priv, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		f.jwksCalls.Add(1)
		if r.Header.Get("X-AOS-Publishable-Key") != "pk_test_x" {
			http.Error(w, "no key", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": f.kid, "x": b64.EncodeToString(pub)}}})
	})
	mux.HandleFunc("/v1/can", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk_test_x.secret" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 401, "error": map[string]any{"code": "invalid_key", "message": "the key is missing or not valid"}})
			return
		}
		var req CanRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		allowed := req.Permission == "invoice.read"
		reason := "allowed"
		if !allowed {
			reason = "no_matching_grant"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 200, "data": map[string]any{"allowed": allowed, "reason": reason}})
	})
	mux.HandleFunc("/v1/can/batch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Checks []CanRequest `json:"checks"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var results []map[string]any
		for _, c := range req.Checks {
			ok := c.Permission == "invoice.read" && c.Resource == (Resource{Type: "organization", ID: "acme"})
			results = append(results, map[string]any{"allowed": ok, "reason": "x"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"results": results}})
	})
	mux.HandleFunc("/v1/users/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 404, "error": map[string]any{"type": "not_found", "code": "not_found", "message": "user not found"}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEngine) sign(claims map[string]any, kid string, key ed25519.PrivateKey) string {
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	signed := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return signed + "." + b64.EncodeToString(ed25519.Sign(key, []byte(signed)))
}

func (f *fakeEngine) client(t *testing.T) *Client {
	c, err := New(Config{URL: f.srv.URL, PublishableKey: "pk_test_x", SecretKey: "sk_test_x.secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerifyToken(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	now := time.Now()
	good := f.sign(map[string]any{"sub": "u1", "sid": "s1", "tid": "t1", "org": "acme", "exp": now.Add(time.Minute).Unix()}, f.kid, f.priv)
	claims, err := c.VerifyToken(context.Background(), good)
	if err != nil || claims.UserID != "u1" || claims.Organization != "acme" || claims.SessionID != "s1" {
		t.Fatalf("good token: %v %+v", err, claims)
	}
	// Keys are cached.
	c.VerifyToken(context.Background(), good)
	if f.jwksCalls.Load() != 1 {
		t.Fatalf("keys fetched %d times", f.jwksCalls.Load())
	}
	expired := f.sign(map[string]any{"sub": "u1", "exp": now.Add(-2 * time.Minute).Unix()}, f.kid, f.priv)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	forged := f.sign(map[string]any{"sub": "u1", "exp": now.Add(time.Minute).Unix()}, f.kid, otherKey)
	unknownKid := f.sign(map[string]any{"sub": "u1", "exp": now.Add(time.Minute).Unix()}, "nope", f.priv)
	tampered := good[:len(good)-4] + "AAAA"
	for name, tok := range map[string]string{"expired": expired, "forged": forged, "unknown kid": unknownKid, "tampered": tampered, "garbage": "a.b", "empty": ""} {
		if _, err := c.VerifyToken(context.Background(), tok); err != ErrInvalidToken {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// An unknown key may cause one refetch, not a fetch per request.
	calls := f.jwksCalls.Load()
	for i := 0; i < 5; i++ {
		c.VerifyToken(context.Background(), unknownKid)
	}
	if f.jwksCalls.Load() > calls+1 {
		t.Fatalf("unknown keys caused %d fetches", f.jwksCalls.Load()-calls)
	}
}

func TestMiddlewareAndRequirePermission(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	token := f.sign(map[string]any{"sub": "u1", "sid": "s1", "exp": time.Now().Add(time.Minute).Unix()}, f.kid, f.priv)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(ClaimsFrom(r.Context()).UserID)) })
	read := c.Middleware(c.RequirePermission("invoice.read", Root)(ok))
	refund := c.Middleware(c.RequirePermission("invoice.refund", Root)(ok))
	call := func(h http.Handler, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call(read, token); w.Code != 200 || w.Body.String() != "u1" {
		t.Fatalf("allowed: %d %s", w.Code, w.Body)
	}
	if w := call(refund, token); w.Code != 403 || !strings.Contains(w.Body.String(), "no_matching_grant") {
		t.Fatalf("denied: %d %s", w.Code, w.Body)
	}
	if w := call(read, ""); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	opt := c.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ClaimsFrom(r.Context()) != nil {
			t.Error("claims without a token")
		}
	}))
	call(opt, "")
}

func TestErrorsAreTyped(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	_, err := c.GetUser(context.Background(), "missing")
	if !IsCode(err, "not_found") {
		t.Fatalf("not found: %v", err)
	}
	bad, _ := New(Config{URL: f.srv.URL, SecretKey: "sk_test_x.wrong"})
	if _, err := bad.Can(context.Background(), CanRequest{}); !IsCode(err, "invalid_key") {
		t.Fatalf("bad key: %v", err)
	}
	if _, err := New(Config{URL: f.srv.URL, SecretKey: "pk_test_oops"}); err == nil {
		t.Fatal("a publishable key was accepted as a secret key")
	}
	if _, err := New(Config{URL: "not a url"}); err == nil {
		t.Fatal("a bad URL was accepted")
	}
}

func TestVerifyWebhook(t *testing.T) {
	body := []byte(`{"id":"d1","event":"user.created","created_at":"2026-11-07T10:00:00Z","data":{"user_id":"u1"}}`)
	now := time.Unix(1_800_000_000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte("whsec"))
	mac.Write([]byte(ts + "." + string(body)))
	header := "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
	ev, err := verifyWebhookAt("whsec", header, body, 0, now)
	if err != nil || ev.Type != "user.created" {
		t.Fatalf("good delivery: %v %+v", err, ev)
	}
	if _, err := verifyWebhookAt("other", header, body, 0, now); err != ErrBadSignature {
		t.Fatal("wrong secret accepted")
	}
	if _, err := verifyWebhookAt("whsec", header, append(body, ' '), 0, now); err != ErrBadSignature {
		t.Fatal("changed body accepted")
	}
	if _, err := verifyWebhookAt("whsec", header, body, 0, now.Add(10*time.Minute)); err != ErrBadSignature {
		t.Fatal("old delivery accepted")
	}
}

func TestCanHandler(t *testing.T) {
	f := newFake(t)
	h := f.client(t).CanHandler()
	token := f.sign(map[string]any{"sub": "u1", "sid": "s1", "org": "acme", "exp": time.Now().Add(time.Minute).Unix()}, f.kid, f.priv)
	post := func(tok, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/aos/can", strings.NewReader(body))
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post("", `{"permissions":["invoice.read"]}`); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	// Without a resource, the active organization from the token is asked about.
	w := post(token, `{"permissions":["invoice.read","invoice.refund"]}`)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"results":{"invoice.read":true,"invoice.refund":false}}` {
		t.Fatalf("answers: %d %s", w.Code, w.Body)
	}
	if w := post(token, `{"permissions":["invoice.read"],"resource":{"type":"organization","id":"other"}}`); !strings.Contains(w.Body.String(), `"invoice.read":false`) {
		t.Fatalf("another resource: %s", w.Body)
	}
}
