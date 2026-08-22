# AOS Go SDK — Developer Guide

This guide explains how to embed AOS in your Go application: configure the SDK, run migrations, wire HTTP routes, and use auth, organizations, and authorization.

For schema details see [`SCHEMA.md`](./SCHEMA.md). For internal design see [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## Mental model

AOS is an **embedded identity layer** inside your app and database:

- **One install per customer database** — no multi-tenant `tenants` table.
- **Auth** — sign-up, login, sessions, MFA, passkeys, OAuth.
- **Organizations** (optional) — teams/workspaces with memberships and an **active org** on the session.
- **Authorization** — RBAC via `Can(user, scope, permission)`; your app owns business tables (e.g. `payments.organization_id`).

You choose URLs, route prefixes, and which handlers to expose. AOS provides handler functions and middleware — not a fixed public API surface.

---

## Prerequisites

- Go 1.22+
- PostgreSQL
- Environment variable `DATABASE_URL` (or pass `Config.Storage`)

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/myapp"
```

Optional for MFA:

```bash
export MFA_ENCRYPTION_KEY="$(openssl rand -hex 32)"
```

---

## 1. Initialize the SDK

```go
package main

import (
    "context"
    "log"
    "os"

    aos "github.com/Esubalew-Sintie/aos-auth-go"
)

func main() {
    ctx := context.Background()

    sdk, err := aos.New(ctx, aos.Config{
        DatabaseURL: os.Getenv("DATABASE_URL"),

        // Optional: enable the organization layer
        Organization: &aos.OrganizationConfig{
            Enabled: true, // AutoSetActiveOnLogin defaults to true
        },

        // Optional: auth methods
        Auth: aos.AuthConfig{
            Password: aos.Bool(true),
            MFA: &aos.MFAConfig{
                EncryptionKey: os.Getenv("MFA_ENCRYPTION_KEY"),
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    if err := sdk.Migrate(ctx); err != nil {
        log.Fatal(err)
    }

    // See sections 2–4 for routing and usage
}
```

### Configuration reference

| Field | Purpose |
|-------|---------|
| `DatabaseURL` | Postgres connection string |
| `Storage` | Optional pre-built storage adapter (overrides `DatabaseURL`) |
| `Auth.Password` | Email/password login (`nil` = enabled) |
| `Auth.MFA` | TOTP MFA; requires `EncryptionKey` |
| `Auth.Passkey` | WebAuthn / passkeys |
| `Auth.OAuth` | Social login providers |
| `Organization.Enabled` | Org APIs, memberships, org-scoped `RequirePermission` |
| `Organization.AutoSetActiveOnLogin` | After login, pick first org membership (default `true` when orgs enabled) |
| `AdminPermission` | Permission for default admin routes in `sdk.Handler()` (default `user.read`) |
| `RedisAddr` | Cache for authorization (default `localhost:6379`) |
| `EventsStrict` | Fail plugin/event handlers on first error |

### Organization modes

**Organizations enabled** (`Organization.Enabled: true`):

- Users can belong to multiple orgs.
- Session has an **active organization** (business UUID in API; IAM id stored internally).
- `RequirePermission("perm")` checks permission in the **active org** scope.
- Login can auto-select an org when the user has memberships.

**Organizations disabled** (omit `Organization` or `Enabled: false`):

- No org create/invite APIs.
- `RequirePermission` scopes to the **INSTALLATION** resource (bootstrap Owner).
- Suitable for single-workspace apps or when you model scope yourself.

---

## 2. Database migrations

Always call `Migrate` before serving traffic:

```go
if err := sdk.Migrate(ctx); err != nil {
    log.Fatal(err)
}
```

Migrations are versioned and idempotent. v2 adds org-scoped roles and stores `user_sessions.active_resource_id` as `iam_resources.id`.

On an existing database, v2 automatically rewrites session values that previously stored business UUIDs.

---

## 3. First-time setup

### Option A — Empty database (you own setup)

After `Migrate`, tables exist but there is no Owner user. Your app registers permissions, creates roles, and assigns memberships (see [Programmatic RBAC](#programmatic-rbac)).

### Option B — Bootstrap (quick start)

Creates INSTALLATION resource, system **Owner** role, and the first admin user:

```go
result, err := sdk.Bootstrap(ctx, aos.BootstrapInput{
    TenantName:     "My App",
    WithDefaultOrg: true,
    OrgName:        "Default Organization",
    Owner: aos.BootstrapOwner{
        Email:     "admin@example.com",
        Password:  "secure-password",
        FirstName: "Admin",
        LastName:  "User",
    },
})
// result.SessionToken, result.UserID, result.OrgID (if WithDefaultOrg)
```

Bootstrap is a **one-time** operation. It fails if an Owner role already exists.

---

## 4. HTTP integration

Two patterns are supported. **Prefer `Handlers()`** for production apps that own their URL layout.

### Pattern A — Default routes (quick start / dev)

Mount all `/v1/*` routes in one call:

```go
http.ListenAndServe(":8080", sdk.Handler())
```

Reference: [`cmd/devserver/main.go`](./cmd/devserver/main.go)

### Pattern B — Custom routes (recommended)

Mount individual handlers on your own paths:

```go
handlers := sdk.Handlers()
requireSession := sdk.Middleware().RequireSession()
requireAdmin := sdk.Middleware().RequirePermission("user.read")

r := chi.NewRouter()

// Public
r.Get("/health", handlers.Health)
r.Post("/login", handlers.Auth().Login)
r.Post("/register", handlers.Auth().Register)

// Session required
r.Group(func(r chi.Router) {
    r.Use(requireSession)
    r.Get("/me", handlers.Auth().Me)
    r.Post("/set-context", handlers.Auth().SetContext)
    r.Post("/iam/can", handlers.IAM().Can)
})

// Admin: session + permission
r.Group(func(r chi.Router) {
    r.Use(requireSession)
    r.Use(requireAdmin)
    r.Post("/admin/organizations", handlers.Organizations().Create)
    r.Get("/admin/users", handlers.Management().GetUsers)
})
```

Use this when you need full control over URL layout and middleware order.

Reference: [`cmd/embedserver/main.go`](./cmd/embedserver/main.go) + [`cmd/embedserver/routes.go`](./cmd/embedserver/routes.go)

### Default `/v1/*` layout (CLI boilerplate)

The CLI generates route wiring in **`initiator/aos_routes.go`** — not in the SDK. That keeps URL prefixes and which handler groups are exposed as **your** code to edit:

```go
// initiator/routes.go (generated)
func InitRoutes(r chi.Router, aosApp *sdk.AOS) {
    r.Get("/health", aosApp.Handlers().Health)
    mountAOSRoutes(r, aosApp) // initiator/aos_routes.go — edit paths here

    r.Route("/api/v1", func(r chi.Router) {
        // your business handlers
    })
}
```

When you scaffold with the React admin UI, the generator adds `/v1/management/*` when `organizations.enabled` is true in `aos.config.ts`. The `@aos-auth/react` client calls these paths directly (no legacy `/v1/admin/*`).

The SDK does **not** ship opinionated path names for embed mode — only `Handlers()` and `Middleware()`.

### Where `Migrate` and `Bootstrap` run

The SDK examples in sections 1–3 call `New`, `Migrate`, and optionally `Bootstrap` in one `main`. **Production and CLI-generated projects split that across commands:**

| Step | Typical location | SDK call |
|------|------------------|----------|
| 1. Config | `aos/config.go` → `SDKConfig()` | `aos.Config{ DatabaseURL, Organization, Auth }` |
| 2. Construct SDK | `aos.New(ctx)` | `aos.New(ctx, SDKConfig())` |
| 3. Migrate schema | `go run ./cmd/migrate` | `sdk.Migrate(ctx)` |
| 4. First-time setup | `go run ./cmd/seed` (once) | `sdk.Bootstrap(...)` + app permission seed |
| 5. Serve HTTP | `go run ./cmd` → `initiator.Run()` | `aos.Init(ctx)` then mount routes |

**Do not** open a second Postgres pool in `initiator` for AOS — the SDK already owns storage via `DatabaseURL`. The initiator only:

1. Calls `aos.Init(ctx)` (wraps `New` + optional event hooks)
2. Creates chi + middleware
3. Calls `InitRoutes` (`mountAOSRoutes` in `initiator/aos_routes.go`) and your `/api/v1/*` business routes
4. Handles graceful shutdown

```go
// initiator/initiator.go (intended shape)
func Run(ctx context.Context) error {
    cfg := LoadConfig()

    aosApp, err := aos.Init(ctx)
    if err != nil {
        return err
    }

    r := chi.NewRouter()
    r.Use(middleware.Logger, middleware.Recoverer)
    InitRoutes(r, aosApp) // mountAOSRoutes in initiator/aos_routes.go + /api/v1/*

    // ... ListenAndServe + graceful shutdown
}
```

Run `go run ./cmd/migrate` (or `go run ./cmd/seed` on a fresh DB) **before** `go run ./cmd`.

### Handler groups

| Group | Access | Examples |
|-------|--------|----------|
| `handlers.Health()` | Public | `GET /health` |
| `handlers.Auth()` | Mixed | Login, register, logout, me, set-context |
| `handlers.MFA()` | Mixed | Enroll, verify login |
| `handlers.Passkey()` | Mixed | Register, authenticate |
| `handlers.OAuth()` | Public | Social login + callback |
| `handlers.Organizations()` | Usually admin | Create, invite, members |
| `handlers.IAM()` | Session | `Can`, check permission |
| `handlers.Context()` | Session | List orgs, permissions, members |
| `handlers.Management()` | Admin | Users, roles, audit logs |

### Middleware

| Middleware | Behavior |
|------------|----------|
| `Middleware().RequireSession()` | Validates `Authorization: Bearer <token>` or `aos_session` cookie; sets user + org context |
| `Middleware().OptionalSession()` | Same, but allows anonymous requests |
| `Middleware().RequirePermission("code")` | Session + `Can()` on **implicit scope** (active org or installation) |

Session token is read from:

1. `Authorization: Bearer <token>`
2. Cookie `aos_session`

---

## 5. Authentication flows

### Sign up

**HTTP:** `POST /register` (or your custom path → `handlers.Auth().Register`)

**Programmatic:**

```go
out, err := sdk.Auth().SignUp(ctx, aos.RegisterInput{
    Email:     "user@example.com",
    Password:  "password123",
    FirstName: "Jane",
    LastName:  "Doe",
})
// out.UserID, out.SessionToken
```

Sign-up creates a **user only**. It does not create an organization.

### Login

**HTTP:** `POST /login` with `{ "email", "password" }`

Response:

```json
{
  "session_token": "...",
  "user_id": "..."
}
```

If MFA is enabled, response includes `mfa_required: true` and `mfa_token`; complete via `handlers.MFA().VerifyLogin`.

When organizations are enabled and `AutoSetActiveOnLogin` is true, the SDK sets the active org to the user's first org membership (if any).

### Session validation

**Programmatic:**

```go
sess, err := sdk.Auth().ValidateSession(ctx, sessionToken)
// sess.UserID, sess.ActiveResourceID (org business UUID), sess.ActiveResourceIAMID
```

### Logout

```go
_ = sdk.Auth().Logout(ctx, sessionToken)
```

---

## 6. Organizations

Requires `Organization.Enabled: true`.

### Create an organization

**HTTP:** `POST /admin/organizations` with session + admin permission:

```json
{ "name": "Acme Corp" }
```

Response: `{ "organizationId": "<business-uuid>" }`

**Programmatic:**

```go
orgID, err := sdk.Organizations().Create(ctx, aos.CreateOrgInput{
    UserID:       creatorUserID,
    SessionToken: sessionToken, // optional; sets active org on creator's session
    Name:         "Acme Corp",
})
```

Create automatically:

1. Creates the org in IAM
2. Adds creator as member with system **Owner** role
3. Sets active org on the session (when `SessionToken` is provided)

### Switch active organization

Users with multiple orgs switch context without re-login.

**HTTP:** `POST /set-context` or `POST /organizations/{id}/activate` (session required):

```json
{ "organization_id": "<business-uuid>" }
```

**Programmatic:**

```go
err := sdk.Organizations().Activate(ctx, userID, sessionToken, orgBusinessUUID)
// or
_, err := sdk.Auth().SetActiveResource(ctx, aos.SetContextInput{
    SessionToken: token,
    ResourceID:   orgBusinessUUID,
})
```

### Login and /me organization payload

When `Organization.Enabled` is true, login, MFA verify, passkey login, invite accept, set-context, and `/me` include:

```json
{
  "session_token": "...",
  "user_id": "...",
  "organization": {
    "active": { "id": "...", "name": "...", "role_id": "...", "role_name": "Owner" },
    "available": [ ... ],
    "needs_selection": false
  },
  "permissions": ["*"],
  "role_id": "..."
}
```

If the user belongs to multiple orgs and none is active, `needs_selection` is `true`.

### List user's organizations

**HTTP:** `GET /context/organizations` (session required)

**Programmatic:**

```go
orgs, err := sdk.Context().ListOrganizations(ctx, userID)
```

### Invite members

**HTTP:** `POST /admin/organizations/{id}/invite`

**Programmatic:**

```go
result, err := sdk.Organizations().Invite(ctx, "", orgID, "new@example.com", roleID)
```

---

## 7. Authorization

### Implicit scope (`RequirePermission`)

Use on routes that should respect the user's **current context**:

```go
r.Use(sdk.Middleware().RequireSession())
r.Use(sdk.Middleware().RequirePermission("invoice.create"))
r.Post("/invoices", createInvoiceHandler)
```

Scope resolution:

| Config | Scope used for `Can()` |
|--------|-------------------------|
| Orgs enabled | Active org (`iam_resources.id` internally) |
| Orgs disabled | INSTALLATION resource |

No `?resourceId=` query parameter is required.

### Explicit checks (`Authz().Can`)

Use when checking permission on a **specific** resource (e.g. a payment's org):

```go
allowed, err := sdk.Authz().Can(ctx, aos.AuthzInput{
    UserID:     userID,
    ResourceID: orgBusinessUUID, // business UUID or IAM id — both resolved
    Permission: "payment.refund",
})
```

**HTTP:** `POST /iam/can` with body `{ "permission": "payment.refund", "resource_id": "..." }`. Omit `resource_id` to use the session's active scope.

### Register permissions and roles

Your app defines permission codes and roles:

```go
_, _ = sdk.Permissions().Register(ctx, aos.RegisterPermissionInput{
    Code:         "invoice.create",
    ResourceType: "ORGANIZATION",
    Action:       "create",
})

roleID, _ := sdk.Roles().Create(ctx, aos.CreateRoleInput{
    Name:           "Billing Admin",
    Description:    "Can manage invoices",
    OrganizationID: orgBusinessUUID, // omit for system/global role
})

_ = sdk.Roles().Grant(ctx, roleID, "invoice.create")
```

Assign roles via memberships (see bootstrap or organization invite flows).

### Request context helpers

After `RequireSession`, read identity from `context.Context`:

```go
userID := aos.UserIDFromContext(r.Context())
orgID  := aos.ActiveResourceIDFromContext(r.Context()) // business org UUID
```

Use these in your business handlers to filter data by `organization_id`.

---

## 8. End-to-end workflow

```text
┌─────────────────────────────────────────────────────────────────┐
│ 1. aos.New(Config{ Organization: { Enabled: true } })           │
│ 2. sdk.Migrate(ctx)                                             │
│ 3. sdk.Bootstrap(...)  OR  your own setup                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Mount handlers (Handlers() + your router)                    │
│ 5. POST /register  → user + session                             │
│ 6. POST /admin/organizations → org + membership + active org    │
│ 7. Register permissions / roles for your domain                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. Protect routes: RequireSession + RequirePermission           │
│ 9. Business tables store organization_id (your UUID column)     │
│10. Authz().Can(user, orgID, "your.permission") on domain ops   │
└─────────────────────────────────────────────────────────────────┘
```

### Example: protect a custom handler

```go
func createPaymentHandler(w http.ResponseWriter, r *http.Request) {
    orgID := aos.ActiveResourceIDFromContext(r.Context())
    userID := aos.UserIDFromContext(r.Context())

    allowed, err := sdk.Authz().Can(r.Context(), aos.AuthzInput{
        UserID:     userID,
        ResourceID: orgID,
        Permission: "payment.create",
    })
    if err != nil || !allowed {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

    // Insert into your payments table with organization_id = orgID
}
```

Or rely on middleware:

```go
r.With(requireSession, requirePaymentCreate).Post("/payments", createPaymentHandler)
```

---

## 9. Programmatic API summary

| API | Purpose |
|-----|---------|
| `sdk.Migrate(ctx)` | Run database migrations |
| `sdk.Bootstrap(ctx, in)` | One-time Owner + optional default org |
| `sdk.Handler()` | All default `/v1/*` routes (devserver convenience only) |
| `sdk.Handlers()` | Individual HTTP handlers — use for custom routes |
| `sdk.Middleware()` | Session and permission middleware |
| `sdk.Auth()` | SignUp, Login, Logout, ValidateSession, SetActiveResource |
| `sdk.Authz()` | `Can()` |
| `sdk.Organizations()` | Create, Invite |
| `sdk.Context()` | ListOrganizations, ListPermissions, ListOrgMembers |
| `sdk.Roles()` | Create, Grant, GetByName |
| `sdk.Permissions()` | Register |
| `sdk.Resources()` | Create IAM resources |
| `sdk.Memberships()` | Add, AssignRole |
| `sdk.Events()` | In-process event bus |

---

## 10. Events

Hook into auth lifecycle without forking the SDK:

```go
sdk.Events().On("user.created", func(ctx context.Context, payload any) error {
    // Send welcome email, sync to CRM, etc.
    return nil
})
```

Set `EventsStrict: true` in config to propagate handler errors.

---

## 11. Local development

```bash
cd IDASS/sdk/go

export DATABASE_URL="postgres://postgres:postgres@localhost:5433/aos_idaas"

# Default /v1/* routes
go run ./cmd/devserver

# Custom routes (embed pattern)
go run ./cmd/embedserver
```

Both enable organizations by default. Override with your own `aos.Config` as needed.

---

## 12. Important conventions

| Concept | Public API | Stored internally |
|---------|------------|-------------------|
| Organization id | Business UUID (`organization_id`) | `iam_resources.id` on session |
| Active org on session | Returned as `organization_id` / `active_resource_id` | `user_sessions.active_resource_id` = IAM id |
| `Authz().Can` resource | Business UUID or IAM id (auto-resolved) | Evaluated from IAM resource tree |

Do not expose `iam_resources`, `resource_type`, or raw RBAC tables in your public API. Use organization UUIDs in your app schema.

---

## 13. Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `missing authorization scope` on admin routes | Orgs enabled but no active org; call `SetActiveResource` or ensure user has org membership + login auto-set |
| `organizations not enabled` | Set `Organization.Enabled: true` |
| `MFA required` on Login | User has MFA; use MFA verify flow |
| `Auth.MFA.EncryptionKey ... required` | Set key in config or `MFA_ENCRYPTION_KEY` env |
| Migration fails on v2 | Orphaned `active_resource_id` values; v2 clears unresolved ones |
| `RequirePermission` returns **403** `no active organization` when orgs are enabled but session has no active org |

---

## Supported API reference

See [`SUPPORTED_API.md`](./SUPPORTED_API.md) for the v0.3 supported surface and deprecation list.

---

## Related docs

- [`SDK.md`](./SDK.md) — short overview and links
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — internal modules and storage
- [`SCHEMA.md`](./SCHEMA.md) — database tables
- [`cmd/devserver/main.go`](./cmd/devserver/main.go) — default routes example
- [`cmd/embedserver/main.go`](./cmd/embedserver/main.go) — custom routes example
