# AOS Go SDK

**Modular inside, simple outside** — embedded Auth + AuthZ for Go applications.

Your app owns URLs, business tables, and domain permissions. AOS provides sessions, organizations (optional), and RBAC primitives.

**→ Start here: [`DEVELOPER.md`](./DEVELOPER.md)** — full integration guide.

**→ API surface: [`SUPPORTED_API.md`](./SUPPORTED_API.md)** — supported vs deprecated exports (v0.3).

See also: [`ARCHITECTURE.md`](./ARCHITECTURE.md) · [`SCHEMA.md`](./SCHEMA.md)

---

## Quick start

```go
sdk, err := aos.New(ctx, aos.Config{
    DatabaseURL: os.Getenv("DATABASE_URL"),
    Organization: &aos.OrganizationConfig{
        Enabled: true,
    },
})
sdk.Migrate(ctx)

// Option 1: all default /v1/* routes
http.ListenAndServe(":8080", sdk.Handler())

// Option 2: your own URLs (recommended)
handlers := sdk.Handlers()
requireSession := sdk.Middleware().RequireSession()
// mount handlers.Auth().Login, etc.
```

Run locally:

```bash
export DATABASE_URL=postgres://...
go run ./cmd/devserver      # default routes
go run ./cmd/embedserver    # custom routes example
```

---

## What you get

| Layer | SDK surface |
|-------|-------------|
| Auth | `Handlers().Auth()`, `Auth().SignUp/Login/Logout` |
| Organizations | `OrganizationConfig`, `Handlers().Organizations()`, `Organizations().Create` |
| Authorization | `Middleware().RequirePermission`, `Authz().Can` |
| Admin | `Handlers().Management()` |
| Migrations | `Migrate(ctx)` |

---

## Configuration (essentials)

```go
aos.Config{
    DatabaseURL: "...",
    Organization: &aos.OrganizationConfig{
        Enabled:              true,
        AutoSetActiveOnLogin: aos.Bool(true), // default when Enabled
    },
    Auth: aos.AuthConfig{
        Password: aos.Bool(true),
        MFA:      &aos.MFAConfig{EncryptionKey: os.Getenv("MFA_ENCRYPTION_KEY")},
        Passkey:  &aos.PasskeyConfig{RPID: "localhost", Origins: []string{"http://localhost:3000"}},
    },
}
```

---

## HTTP vs programmatic

| Use case | Approach |
|----------|----------|
| REST API for frontend | `sdk.Handlers()` + your router + middleware |
| Internal / gRPC / jobs | `sdk.Auth()`, `sdk.Authz()`, `sdk.Organizations()` |
| Prototype / dev | `sdk.Handler()` |

---

## Packages

| Import | Role |
|--------|------|
| `github.com/Esubalew-Sintie/aos-auth-go` | Public SDK |

---

## Examples in this repo

| Path | Description |
|------|-------------|
| [`cmd/devserver`](./cmd/devserver/main.go) | Default `/v1/*` routes, orgs enabled |
| [`cmd/embedserver`](./cmd/embedserver/main.go) | Custom paths, session + permission groups |
| [`DEVELOPER.md`](./DEVELOPER.md) | Complete developer guide |
