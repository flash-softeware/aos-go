# aos-go

The Go SDK for AOS, the identity engine: check session tokens, ask about permissions, guard routes, and manage users, roles, organizations, API keys and webhooks. It has no dependencies outside the standard library.

```sh
go get github.com/flash-software-technology/aos-go
```

```go
import aos "github.com/flash-software-technology/aos-go"

client, err := aos.New(aos.Config{
    URL:            os.Getenv("AOS_URL"),             // the engine, such as the hosted service
    PublishableKey: os.Getenv("AOS_PUBLISHABLE_KEY"), // to check tokens
    SecretKey:      os.Getenv("AOS_SECRET_KEY"),      // for backend calls; never in a browser
})

mux.Handle("GET /api/me", client.Middleware(meHandler))              // 401 without a valid token
mux.Handle("GET /api/invoices", client.Middleware(
    client.RequirePermission("invoice.read", aos.ActiveOrganization)(invoices))) // 403 without the permission
mux.Handle("POST /api/aos/can", client.CanHandler())                // answers <Protect> in @aos-auth/react
mux.Handle("POST /api/webhooks/aos", aos.WebhookHandler(secret, onEvent))
```

In a handler, `aos.ClaimsFrom(r.Context())` gives the signed-in person: `UserID`, `SessionID`, and `Organization` (the active organization's slug, when there is one).

## What it covers

| Area | Methods |
| --- | --- |
| Requests | `Middleware`, `Optional`, `RequirePermission`, `CanHandler`, `VerifyToken`, `TokenFromRequest`, `ClaimsFrom` |
| Permissions | `Can`, `CanBatch`, `Filter`, `Explain`, `PutPermission`, `PutRole`, `PutResource`, `CreateGrant`, `DeleteGrant` |
| Users and organizations | `CreateUser`, `GetUser`, `ListUsers`, `SuspendUser`, `ReinstateUser`, `DeleteUser`, `CreateOrganization`, `ListOrganizations`, `ListMembers`, `Invite` |
| Machines and events | `CreateAPIKey`, `CheckAPIKey`, `CreateWebhook`, `VerifyWebhook`, `WebhookHandler` |

Tokens are checked locally against the engine's public keys, which are fetched once and cached. A permission deny is an answer (`CanResult.Allowed == false`, with a `Reason`), not an error. Engine errors are `*aos.APIError` with a stable `Code`.

## Hosted or embedded

`aos.Auth` lists every method above. `*aos.Client` talks to an engine over HTTP. The engine's `embed` package runs the engine inside your own Go backend, with your own Postgres, and has the same methods. Write your code against `aos.Auth` and only the constructor changes between the two.

## Tests

```sh
go test ./...                              # unit tests
go test -tags integration ./...            # against a running engine: needs AOS_IT_URL, AOS_IT_PUBLISHABLE_KEY, AOS_IT_SECRET_KEY
```
