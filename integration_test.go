//go:build integration

package aos

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Run with: ../scripts/with-engine.sh go test -tags integration ./...

func engine(t *testing.T) (*Client, string, string, string) {
	url, pk, sk := os.Getenv("AOS_IT_URL"), os.Getenv("AOS_IT_PUBLISHABLE_KEY"), os.Getenv("AOS_IT_SECRET_KEY")
	if url == "" {
		t.Skip("no engine: run through scripts/with-engine.sh")
	}
	c, err := New(Config{URL: url, PublishableKey: pk, SecretKey: sk})
	if err != nil {
		t.Fatal(err)
	}
	return c, url, pk, sk
}

// front calls a frontend route as a browser would in development.
func front(t *testing.T, url, pk, method, path string, body any, session string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, url+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AOS-Publishable-Key", pk)
	if session != "" {
		req.Header.Set("X-AOS-Session", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %v", method, path, resp.StatusCode, out)
	}
	return out
}

func TestAgainstARealEngine(t *testing.T) {
	c, url, pk, _ := engine(t)
	ctx := context.Background()
	email := "go-sdk-" + time.Now().Format("150405.000") + "@example.com"

	// A person signs up; the token comes from the development inbox.
	front(t, url, pk, "POST", "/v1/sign-up", map[string]any{"email": email, "password": "a-long-test-password"}, "")
	var token string
	for i := 0; i < 50 && token == ""; i++ {
		resp, err := http.Get(url + "/dev/mail?to=" + email)
		if err != nil {
			t.Fatal(err)
		}
		var mail struct {
			Data []struct {
				Token string `json:"token"`
			} `json:"data"`
		}
		json.NewDecoder(resp.Body).Decode(&mail)
		resp.Body.Close()
		if len(mail.Data) > 0 {
			token = mail.Data[0].Token
		}
		time.Sleep(100 * time.Millisecond)
	}
	if token == "" {
		t.Fatal("no confirmation email in the development inbox")
	}
	signedIn := front(t, url, pk, "POST", "/v1/verify-email", map[string]any{"token": token}, "")
	session := signedIn["data"].(map[string]any)["session_token"].(string)
	userID := signedIn["data"].(map[string]any)["user"].(map[string]any)["id"].(string)
	jwt := front(t, url, pk, "POST", "/v1/session/token", nil, session)["data"].(map[string]any)["token"].(string)

	// The backend verifies the token locally.
	claims, err := c.VerifyToken(ctx, jwt)
	if err != nil || claims.UserID != userID {
		t.Fatalf("verify: %v %+v", err, claims)
	}

	// Permissions as code, a grant, and the checks.
	if _, err := c.PutPermission(ctx, Permission{Name: "invoice.read"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutRole(ctx, Role{Name: "Accountant", Permissions: []string{"invoice.*"}}); err != nil {
		t.Fatal(err)
	}
	// A resource id of its own, so other suites on the same tenant do not clash.
	invoiceID := "inv-go-" + time.Now().Format("150405.000000")
	org, err := c.CreateOrganization(ctx, "Acme "+time.Now().Format("150405.000"), "", userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutResource(ctx, Resource{Type: "invoice", ID: invoiceID}, &Resource{Type: "organization", ID: org.Slug}, "Invoice 1"); err != nil {
		t.Fatal(err)
	}
	res, err := c.Can(ctx, CanRequest{PrincipalID: userID, Permission: "invoice.read", Resource: Resource{Type: "invoice", ID: invoiceID}})
	if err != nil || !res.Allowed {
		t.Fatalf("owner can read: %v %+v", err, res)
	}
	filter, err := c.Filter(ctx, userID, "invoice.read", "invoice")
	if err != nil || len(filter.Allowed) != 1 || filter.Allowed[0] != invoiceID {
		t.Fatalf("filter: %v %+v", err, filter)
	}
	members, err := c.ListMembers(ctx, org.ID)
	if err != nil || len(members) != 1 || members[0].Roles[0] != "Owner" {
		t.Fatalf("members: %v %+v", err, members)
	}

	// The middleware in front of a real handler.
	h := c.Middleware(c.RequirePermission("invoice.read", func(r *http.Request) Resource { return Resource{Type: "invoice", ID: invoiceID} })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })))
	r := httptest.NewRequest("GET", "/invoices/"+invoiceID, nil)
	r.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("middleware: %d %s", w.Code, w.Body)
	}

	// API keys for a machine.
	key, err := c.CreateAPIKey(ctx, userID, "script", []string{"invoice.read"})
	if err != nil {
		t.Fatal(err)
	}
	check, err := c.CheckAPIKey(ctx, key.Key, "invoice.read", &Resource{Type: "invoice", ID: invoiceID})
	if err != nil || !check.Allowed || check.PrincipalID != userID {
		t.Fatalf("key check: %v %+v", err, check)
	}
	if _, err := c.CheckAPIKey(ctx, key.Key+"x", "", nil); !IsCode(err, "invalid_api_key") {
		t.Fatalf("bad key: %v", err)
	}
	if _, err := c.GetUser(ctx, "00000000-0000-0000-0000-000000000000"); !IsCode(err, "not_found") {
		t.Fatalf("missing user: %v", err)
	}
}
