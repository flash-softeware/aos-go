# aos-go

The Go SDK for AOS: check who is signed in, guard your `net/http` routes by permission, and manage users, roles, organizations, API keys and webhooks from your backend. It uses only the Go standard library.

Part of **AOS**, an identity and access platform (sign-up and sign-in, sessions, MFA, passkeys, SSO, organizations, roles and permissions, webhooks, audit).

## Where it fits

| Piece | What it does | Get it |
| --- | --- | --- |
| [Engine](https://github.com/flash-software-technology/aos) | The auth server: users, sessions, permissions, email | run by `aosctl dev`, or embedded in your Go app |
| [`aosctl`](https://github.com/flash-software-technology/aos-cli) | CLI: new projects, local dev engine, seed data, grants | `go install github.com/flash-software-technology/aos-cli/cmd/aosctl@latest` |
| **aos-go** (this) | Your Go backend talks to the engine | `go get github.com/flash-software-technology/aos-go` |
| [`@aos-auth/js`, `@aos-auth/react`](https://github.com/flash-software-technology/aos-js) | Sign-in in the browser; `<Protect>` hides UI by permission | `npm i @aos-auth/react` |
| [`@aos-auth/node`](https://github.com/flash-software-technology/aos-js), [`aos-auth` for Python](https://github.com/flash-software-technology/aos-python) | The same SDK for Node and Python backends | see their READMEs |

The browser signs the person in and sends a short-lived **access token** (a JWT) with each API call. Your Go backend checks that token with this SDK and asks the engine about permissions.

## Install

```sh
go get github.com/flash-software-technology/aos-go@v0.4.0
```

Needs Go 1.24+. Embedding the engine (see below) needs Go 1.26+.

## Keys

| Key | Looks like | Where it goes |
| --- | --- | --- |
| Publishable key | `pk_...` | Safe in a browser. The SDK uses it to fetch the public keys that verify tokens. |
| Secret key | `sk_...` | **Server only.** Needed for permission checks and admin calls. Never ship it to a browser or log it. |

## Quick start

### 1. Get an engine

**Option A: `aosctl dev` (the easiest way to start).** It runs Postgres in Docker plus the engine, creates a tenant (your app's space in the engine), and writes `AOS_URL`, `AOS_PUBLISHABLE_KEY` and `AOS_SECRET_KEY` into `.env`.

```sh
go install github.com/flash-software-technology/aos-cli/cmd/aosctl@latest
aosctl init my-app --frontend react-vite --backend go --published
cd my-app
aosctl dev                                  # terminal 1: Postgres + engine, writes .env
aosctl seed                                 # sample permissions, roles (Viewer, Billing), user ana@example.com
cd api && go mod tidy && go run .           # terminal 2: Go backend on :4000
cd web && npm install && npm run dev        # terminal 3: open http://localhost:5173
aosctl mail                                 # dev inbox: verification and setup links land here
aosctl grant --user you@example.com --role Viewer
```

Needs Docker and Node 22.9+ for the web app. `aosctl init --backend go` writes a working backend built on this SDK in `api/main.go`.

**Option B: embed the engine in your Go process.** No separate auth server: the engine runs inside your backend and keeps its tables in your own Postgres (in the schemas `aos` and `aos_platform`). See [Embed the engine](#embed-the-engine-in-your-go-app).

### 2. A complete server

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	aos "github.com/flash-software-technology/aos-go"
)

func main() {
	client, err := aos.New(aos.Config{
		URL:            os.Getenv("AOS_URL"),             // such as http://127.0.0.1:8080
		PublishableKey: os.Getenv("AOS_PUBLISHABLE_KEY"), // pk_... to verify tokens
		SecretKey:      os.Getenv("AOS_SECRET_KEY"),      // sk_... for permission and admin calls
	})
	if err != nil {
		log.Fatal(err) // run `aosctl dev` to write .env
	}

	mux := http.NewServeMux()

	// Any signed-in person. Without a valid token: 401.
	mux.Handle("GET /api/me", client.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := aos.ClaimsFrom(r.Context())
		writeJSON(w, map[string]any{"user_id": c.UserID, "session_id": c.SessionID, "organization": c.Organization})
	})))

	// Only people who hold invoice.read in their active organization. Otherwise: 403.
	mux.Handle("GET /api/invoices", client.Middleware(
		client.RequirePermission("invoice.read", aos.ActiveOrganization)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, []string{"INV-1001", "INV-1002"})
			}))))

	// Answers <Protect> in @aos-auth/react.
	mux.Handle("POST /api/aos/can", client.CanHandler())

	// Events from the engine, checked against the endpoint's signing secret.
	mux.Handle("POST /api/webhooks/aos", aos.WebhookHandler(os.Getenv("AOS_WEBHOOK_SECRET"),
		func(r *http.Request, ev *aos.Event) error {
			log.Printf("aos event %s %s", ev.Type, ev.ID)
			return nil
		}))

	log.Println("listening on http://127.0.0.1:4000")
	log.Fatal(http.ListenAndServe("127.0.0.1:4000", mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
```

Go does not read `.env` by itself. Load it into the shell first:

```sh
set -a && . ./.env && set +a
go run .
curl -i http://127.0.0.1:4000/api/me                 # 401 {"status":401,"error":{"code":"unauthenticated",...}}
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4000/api/me
```

`$TOKEN` is an access token from a signed-in browser session (the browser SDK sends it as `Authorization: Bearer ...`).

## Common tasks

### Verify a token yourself

```go
claims, err := client.VerifyToken(ctx, aos.TokenFromRequest(r))
if errors.Is(err, aos.ErrInvalidToken) {
	// malformed, tampered with, from another tenant, or expired
}
```

Tokens are checked **locally**: the signature (EdDSA) against the tenant's public keys (JWKS, from `/v1/jwks.json`) and the expiry, with one minute of clock skew. The keys are fetched once and cached for `KeysTTL` (default 5 minutes). An unknown key id triggers a refetch, at most every 10 seconds. If the engine is unreachable, already-known keys keep working.

`Claims` fields: `UserID`, `SessionID`, `TenantID`, `Organization` (the active organization's id in your app), `OrganizationID` (its id in the engine), `AssuranceLevel` (0 nothing verified, 1 email, 2 phone), `Type`, `IssuedAt`, `ExpiresAt`.

### Guard routes

```go
mux.Handle("GET /api/me", client.Middleware(h))  // 401 without a valid token
mux.Handle("GET /", client.Optional(h))          // lets anonymous requests through; ClaimsFrom returns nil

// Put RequirePermission after Middleware.
mux.Handle("GET /api/reports", client.Middleware(client.RequirePermission("report.read", aos.Root)(h)))
```

The middleware has the signature `func(http.Handler) http.Handler`, so it also works with chi and similar routers.

The second argument of `RequirePermission` says **which resource** the request is about:

- `aos.Root`: the top of the tenant (`{Type: "tenant", ID: "root"}`). A permission held anywhere above counts.
- `aos.ActiveOrganization`: the organization the person is working in, or the root when none is active.
- Your own `aos.ResourceFunc`, for example the invoice in the path:

```go
invoiceFromPath := func(r *http.Request) aos.Resource {
	return aos.Resource{Type: "invoice", ID: r.PathValue("id")}
}
mux.Handle("POST /api/invoices/{id}/refund", client.Middleware(
	client.RequirePermission("invoice.refund", invoiceFromPath)(refund)))
```

### Answer `<Protect>` from the React SDK

```go
mux.Handle("POST /api/aos/can", client.CanHandler())
```

`<Protect>` in `@aos-auth/react` posts `{"permissions": [...], "resource": {"type", "id"}}` with the session token and gets `{"results": {"invoice.read": true}}`. Without a resource, the active organization (or the root) is asked about. At most 100 permissions per request. Hiding UI is only a convenience: always check again on the server with `RequirePermission` or `Can`.

### Check a permission in code

```go
res, err := client.Can(ctx, aos.CanRequest{
	PrincipalID: claims.UserID,
	Permission:  "invoice.refund",
	Resource:    aos.Resource{Type: "invoice", ID: "inv_42"},
	SessionID:   claims.SessionID,                                // lets step-up (fresh MFA) permissions pass
	Context:     map[string]any{"request": map[string]any{"amount": 500}}, // read by grant conditions
})
if err != nil { /* the engine could not answer */ }
if !res.Allowed {
	log.Println(res.Reason) // no_matching_grant, denied_by_grant, step_up_required, approval_required, condition_not_met, ...
}
```

A deny is an answer (`Allowed == false` with a `Reason`), not an error.

- `CanBatch(ctx, []aos.CanRequest)`: up to 100 questions in one call.
- `Filter(ctx, principalID, "invoice.read", "invoice")`: which invoices the person may read, for your own list queries (`Allowed`, `Conditional`, `Truncated`).
- `Explain(ctx, req)`: the path that decided a question, for debugging.

### Define permissions, roles, resources and grants

```go
client.PutPermission(ctx, aos.Permission{Name: "invoice.refund", StepUpSeconds: 300}) // needs MFA within 5 minutes
client.PutRole(ctx, aos.Role{Name: "Billing", Permissions: []string{"invoice.*"}})   // names, prefixes or "*"

// Put your objects in the tree, so a grant on a parent covers its children.
acme := aos.Resource{Type: "organization", ID: "acme"}
client.PutResource(ctx, aos.Resource{Type: "invoice", ID: "inv_42"}, &acme, "Invoice 42")

grantID, err := client.CreateGrant(ctx, aos.Grant{
	PrincipalID: userID, // or GroupID
	Role:        "Billing",
	Resource:    acme,
	// Effect: "deny", Condition: "...", ExpiresAt: &t, Reason: "..." are optional
})
client.DeleteGrant(ctx, grantID)
```

`PutPermission`, `PutRole` and `PutResource` are upserts, so they are safe to run at every start.

### Users and organizations

```go
u, err := client.CreateUser(ctx, "ana@example.com", "Ana", "Viewer", nil) // emails a setup link; role on the root
u, err = client.GetUser(ctx, u.ID)
page, err := client.ListUsers(ctx, "", 50)          // page.Users, page.NextCursor
client.SuspendUser(ctx, u.ID, "unpaid invoice")
client.ReinstateUser(ctx, u.ID)
client.DeleteUser(ctx, u.ID)

org, err := client.CreateOrganization(ctx, "Acme", "acme", u.ID) // u becomes its first Owner
orgs, err := client.ListOrganizations(ctx)
members, err := client.ListMembers(ctx, org.ID)                 // PrincipalID, Email, Roles, ...
client.Invite(ctx, org.ID, "ben@example.com", "Viewer")
```

### API keys for machines

```go
k, err := client.CreateAPIKey(ctx, principalID, "billing-cron", []string{"invoice.read"})
fmt.Println(k.Key) // shown only once

check, err := client.CheckAPIKey(ctx, presentedKey, "invoice.read", nil) // nil resource: the root
if aos.IsCode(err, "invalid_api_key") { /* unknown or revoked */ }
if check.Allowed { /* check.PrincipalID may do it */ }
```

### Webhooks

```go
hook, err := client.CreateWebhook(ctx, "https://api.example.com/api/webhooks/aos", []string{"user.created"})
// hook.Secret is shown only once: store it as AOS_WEBHOOK_SECRET.

mux.Handle("POST /api/webhooks/aos", aos.WebhookHandler(secret, func(r *http.Request, ev *aos.Event) error {
	switch ev.Type {
	case "user.created":
		// json.Unmarshal(ev.Data, &yourStruct)
	}
	return nil // an error answers 500, so the engine retries
}))
```

`WebhookHandler` checks the `X-AOS-Signature` header (`t=<unix>,v1=<hex HMAC-SHA256>`), answers 400 on a bad signature and 204 on success. To verify by hand, use `aos.VerifyWebhook(secret, header, body, tolerance)` (tolerance 0 means 5 minutes); it returns `aos.ErrBadSignature` for a wrong or too-old delivery.

In development, `aosctl webhooks listen --forward http://localhost:4000/api/webhooks/aos` creates a temporary endpoint, forwards deliveries to your backend and prints the signing secret to put in `AOS_WEBHOOK_SECRET`.

### Handle errors

```go
_, err := client.GetUser(ctx, "nope")
var apiErr *aos.APIError
if errors.As(err, &apiErr) {
	log.Println(apiErr.Status, apiErr.Code, apiErr.Message, apiErr.Details)
}
if aos.IsCode(err, "not_found") { /* ... */ }
```

Engine errors are `*aos.APIError` with a stable `Code`. Network failures are ordinary wrapped errors.

## Embed the engine in your Go app

The engine's `embed` package runs AOS inside your own backend, with your own Postgres. `*embed.Auth` implements this SDK's `aos.Auth` interface, so code written against `aos.Auth` works with both `aosctl dev` and the embedded engine. Only the constructor changes.

**Fastest start:** `aosctl init shop --mode embedded --backend go --published` writes a working app (Go backend with the engine inside, React frontend) and `aosctl dev` prepares its database. See the [aosctl README](https://github.com/flash-software-technology/aos-cli#embedded-mode-auth-inside-your-own-backend).

```sh
go get github.com/flash-software-technology/aos@v0.5.0
openssl rand -base64 32        # a master key; or `aos keygen` with the engine binary
```

```go
import (
	aos "github.com/flash-software-technology/aos-go"
	"github.com/flash-software-technology/aos/embed"
)

auth, err := embed.New(ctx, embed.Config{
	DatabaseURL: os.Getenv("DATABASE_URL"),   // your Postgres; schemas are created or upgraded on start
	MasterKey:   os.Getenv("AOS_MASTER_KEY"), // base64 of 32 random bytes; keep out of the database and git
	AppURL:      "http://localhost:4000",      // email links point here; this origin may call the routes
	Origins:     []string{"http://localhost:5173"}, // extra browser origins, such as a dev server
	Development: true,                         // email goes to a dev inbox at /aos/dev/mail
})
if err != nil {
	log.Fatal(err)
}
defer auth.Close()

mux.Handle("/aos/", auth.Handler()) // the routes the browser SDK and email links use
registerRoutes(mux, auth)           // the same code as with aos.New

// Elsewhere in your package: written once against aos.Auth.
func registerRoutes(mux *http.ServeMux, a aos.Auth) {
	mux.Handle("GET /api/invoices", a.Middleware(
		a.RequirePermission("invoice.read", aos.ActiveOrganization)(invoices)))
	mux.Handle("POST /api/aos/can", a.CanHandler())
}
```

In the browser, point `@aos-auth/js` or `@aos-auth/react` at `<AppURL>/aos` with `auth.PublishableKey()`.

| `embed.Config` field | Meaning |
| --- | --- |
| `DatabaseURL`, `MasterKey`, `AppURL` | Required. |
| `Path` | Where `Handler` is mounted. Default `/aos`. |
| `Origins` | More browser origins allowed besides `AppURL`'s. |
| `Slug`, `Name` | The app's tenant. Default `app` and `App`. Created on first start. |
| `Kind` | `multi` (with organizations, default) or `single`. |
| `Development` | Dev inbox at `<Path>/dev/mail` when no SMTP is set. |
| `Sender`, `SMTPAddr`, `SMTPUsername`, `SMTPPassword`, `MailFrom` | Email delivery. |
| `TrustedProxies`, `Logger` | Proxies whose `X-Forwarded-For` is believed; the engine's log. |

`*embed.Auth` also has `Slug()`, `Path()`, `PublishableKey()`, `Engine()` and `Close()`.

## API reference

| Area | Functions and methods |
| --- | --- |
| Setup | `New(Config) (*Client, error)`, `Auth` (interface), `Version` |
| Requests | `Middleware`, `Optional`, `RequirePermission`, `CanHandler`, `VerifyToken`, `TokenFromRequest`, `ClaimsFrom`, `WithClaims`, `Root`, `ActiveOrganization` |
| Permissions | `Can`, `CanBatch`, `Filter`, `Explain`, `PutPermission`, `PutRole`, `PutResource`, `CreateGrant`, `DeleteGrant` |
| Users and organizations | `CreateUser`, `GetUser`, `ListUsers`, `SuspendUser`, `ReinstateUser`, `DeleteUser`, `CreateOrganization`, `ListOrganizations`, `ListMembers`, `Invite` |
| Machines and events | `CreateAPIKey`, `CheckAPIKey`, `CreateWebhook`, `VerifyWebhook`, `WebhookHandler` |
| Errors | `APIError`, `IsCode`, `ErrInvalidToken`, `ErrBadSignature` |

Everything except `VerifyToken`, `Middleware`, `Optional`, `TokenFromRequest` and the webhook helpers calls the engine with the secret key.

## Configuration

| `aos.Config` field | Env var (by convention) | Meaning |
| --- | --- | --- |
| `URL` | `AOS_URL` | The engine's address, such as `http://127.0.0.1:8080`. Required. |
| `PublishableKey` | `AOS_PUBLISHABLE_KEY` | `pk_...`. Needed to verify tokens. |
| `SecretKey` | `AOS_SECRET_KEY` | `sk_...`. Needed for permission checks and admin calls. |
| `HTTPClient` | | Optional. Default: a client with a 10 second timeout. |
| `KeysTTL` | | How long fetched public keys are trusted. Default 5 minutes. |

`AOS_WEBHOOK_SECRET` is used by the examples above for the webhook signing secret.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `aos: Config.URL must be an address such as https://auth.example.com` | `AOS_URL` is empty. Run `aosctl dev` and load `.env` (Go does not read it automatically). |
| `does not look like a secret key (sk_...)` / `publishable key (pk_...)` | The keys are swapped or wrong. The secret key starts with `sk_`, the publishable key with `pk_`. |
| `aos: this call needs Config.SecretKey` | Set `SecretKey`. `RequirePermission` and `CanHandler` need it too, and answer 503 without it. |
| **401** `unauthenticated` | No `Authorization: Bearer <token>` header, or the token is invalid or expired. The browser SDK refreshes tokens; check that your frontend sends it. |
| **403** with a reason code | The person is signed in but lacks the permission. Grant a role: `aosctl grant --user you@example.com --role Viewer`. Check the resource your `ResourceFunc` returns. |
| **503** from `Middleware` | The public keys could not be fetched: engine down, wrong `AOS_URL`, or missing `PublishableKey`. |
| Browser call blocked by CORS | The browser talks to the engine directly; its origin must be allowed (`aosctl dev` sets this up; with `embed`, use `AppURL` and `Origins`). |
| Webhook answers 400 `bad signature` | Wrong `AOS_WEBHOOK_SECRET`, the body was changed before verification, or the clock is off by more than 5 minutes. |

## Developing this package

```
client.go       Config, New, APIError, the HTTP call
auth.go         the Auth interface (also implemented by aos/embed)
token.go        VerifyToken, JWKS cache, Claims
middleware.go   Middleware, Optional, RequirePermission, CanHandler
permissions.go  Can, Filter, roles, resources, grants
admin.go        users, organizations, API keys, webhooks
webhook.go      VerifyWebhook, WebhookHandler
```

```sh
go vet ./...
go test ./...                     # unit tests
go test -tags integration ./...   # against a running engine: set AOS_IT_URL, AOS_IT_PUBLISHABLE_KEY, AOS_IT_SECRET_KEY
```

Point the integration tests at a throwaway engine (for example one from `aosctl dev` in a scratch project), never at real data.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
