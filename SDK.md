# AOS Go SDK v2

AOS provides **identity infrastructure**. Your application owns **business structure**.

## Packages

| Package | npm / Go module | Role |
|---------|-----------------|------|
| Go SDK | `github.com/Esubalew-Sintie/aos-auth-go` | Backend embedded platform |
| Frontend client | `aos-auth` | Login, MFA, passkeys, authz, session context |
| CLI | `aos-cli` (`aos` command) | Migrate, bootstrap, scaffold |

```bash
go get github.com/Esubalew-Sintie/aos-auth-go@v0.1.0
npm install aos-auth aos-cli
```

## Quick start

```go
aos, err := aos.New(ctx, aos.Config{DatabaseURL: os.Getenv("DATABASE_URL")})
if err != nil { log.Fatal(err) }

_ = aos.Migrate(ctx)
result, err := aos.Bootstrap(ctx, aos.BootstrapInput{
    TenantName: "My Application",
    Owner: aos.BootstrapOwner{
        Email:    "owner@example.com",
        Password: "secure-password",
    },
})

http.Handle("/aos/", http.StripPrefix("/aos", aos.Router()))
```

## Bootstrap (Owner + `*` only)

`Bootstrap` creates:
- Tenant + IAM tenant resource
- Role **Owner** with permission `*`
- Owner user with tenant membership + role assignment

No business roles (Merchant Admin, Customer, etc.) are seeded.

## Registration (identity only)

```go
out, err := aos.Auth().SignUp(ctx, aos.RegisterInput{
    Email:    "user@example.com",
    Password: "password",
    TenantID: tenantID,
})
```

Register creates **user + session** and emits `user.created`. It does **not** assign roles or memberships.

### Post-register hook (your application)

```go
aos.Events().On(events.EventUserCreated, func(ctx context.Context, payload any) error {
    e := payload.(events.UserCreatedEvent)
    // 1. Register business permissions
    // 2. Create resource (merchant, team, etc.)
    // 3. Add membership + assign role
    return nil
})
```

## Authorization

```go
allowed, err := aos.Authz().Can(ctx, aos.AuthzInput{
    UserID:     userID,
    ResourceID: merchantID,
    Permission: "payment.refund",
})
```

HTTP: `POST /v1/authz/can` with `{ "resource_id", "permission" }`.

## Programmatic IAM

```go
_, _ = aos.Permissions().Register(ctx, aos.RegisterPermissionInput{Code: "payment.refund"})
roleID, _ := aos.Roles().Create(ctx, aos.CreateRoleInput{TenantID: tid, Name: "Finance"})
_ = aos.Roles().Grant(ctx, roleID, "payment.refund")

iamID, _ := aos.Resources().IAMResourceID(ctx, merchantID, "ORGANIZATION")
_, _ = aos.Memberships().Add(ctx, aos.AddMembershipInput{
    TenantID: tid, UserID: uid, ResourceType: "ORGANIZATION",
    ResourceID: merchantID, RoleID: roleID, IAMResource: iamID,
})
```

## Session context

```go
_, err := aos.Auth().SetActiveResource(ctx, aos.SetContextInput{
    SessionToken: token,
    ResourceID:   merchantID,
})
```

HTTP: `POST /v1/auth/set-context` (alias: `/v1/auth/switch-organization`).

## Public API surface

| Method | Purpose |
|--------|---------|
| `aos.Auth()` | SignUp, Login, Logout, ValidateSession, SetActiveResource |
| `aos.Authz()` | Can (alias: `aos.IAM()`) |
| `aos.Permissions()` | Register permission codes |
| `aos.Roles()` | Create roles, Grant permissions |
| `aos.Resources()` | Create IAM resources, lookup IAM IDs |
| `aos.Memberships()` | Add membership, AssignRole |
| `aos.Organizations()` | Create org, Invite |
| `aos.Events()` | In-process event bus |
| `aos.Context()` | ListOrganizations, ListPermissions, ListOrgMembers (app portal helpers) |
| `aos.Middleware()` | RequireSession, RequirePermission |

## Permission wildcards

| Granted | Matches |
|---------|---------|
| `*` | everything |
| `payment.*` | `payment.read`, `payment.refund`, … |
| `payment.read` | exact only |

DENY beats ALLOW in the authorization engine.

## Deprecated

- Tenant templates (`SAAS_PLATFORM`, etc.) — no longer used by bootstrap
- `/v1/me/*` — reference-portal routes; use `/v1/authz/can` + app APIs
- `portal_context` in auth responses
- `aos.IAM()` — use `aos.Authz()`

## Full example

See [`examples/payment-gateway`](../../examples/payment-gateway/README.md) — self-service merchant signup, business IAM seeding, and `payment.refund` authorization.
