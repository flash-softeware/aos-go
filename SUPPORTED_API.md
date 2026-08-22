# Supported Public API (v0.3)

This document defines the **supported** SDK surface for embedded applications. Other exports remain for backward compatibility and may change or be removed in v1.0.

---

## Supported entry points

| API | Status | Use for |
|-----|--------|---------|
| `aos.New(ctx, Config)` | Supported | Initialize SDK |
| `sdk.Migrate(ctx)` | Supported | Database migrations |
| `sdk.Bootstrap(ctx, BootstrapInput)` | Supported | One-time Owner setup |
| `sdk.Handlers()` | **Preferred** | HTTP handler functions |
| `sdk.Middleware()` | Supported | Session + permission middleware |
| `sdk.Handler()` | Supported (convenience) | All default `/v1/*` routes |
| `sdk.Auth()` | Supported | Programmatic auth |
| `sdk.Authz()` | Supported | `Can()` checks |
| `sdk.Organizations()` | Supported | Create, invite, activate org |
| `sdk.Context()` | Supported | List orgs, permissions, members |
| `sdk.Roles()` | Supported | Create/grant roles (incl. org-scoped) |
| `sdk.Permissions()` | Supported | Register permission codes |
| `sdk.Resources()` | Supported | IAM resource helpers |
| `sdk.Memberships()` | Supported | Membership assignment |
| `sdk.Events()` | Supported | In-process hooks |

---

## Supported configuration

```go
aos.Config{
    DatabaseURL:     "...",
    AdminPermission: "user.read", // default admin gate for sdk.Handler() admin routes
    Organization: &aos.OrganizationConfig{
        Enabled:              true,
        AutoSetActiveOnLogin: aos.Bool(true),
    },
    Auth: aos.AuthConfig{
        Password: aos.Bool(true),
        MFA:      &aos.MFAConfig{EncryptionKey: "..."},
        Passkey:  &aos.PasskeyConfig{RPID: "...", Origins: []string{"..."}},
        OAuth:    []aos.OAuthProviderConfig{...},
    },
}
```

---

## Supported HTTP patterns (Handlers)

Mount with **your URLs**. Recommended groups:

### Public
- `handlers.Health`
- `handlers.Auth().Login`, `Register`, `ForgotPassword`, `ResetPassword`, `VerifyEmail`, `AcceptInvite`
- `handlers.MFA().VerifyLogin`
- `handlers.Passkey().Authenticate`, `AuthenticateVerify`
- `handlers.OAuth().Login`, `Callback`

### Session required
- `handlers.Auth().Logout`, `Me`, `SetContext`, `GetSessions`, …
- `handlers.Organizations().Activate` — `POST /organizations/{id}/activate`
- `handlers.IAM().Can`
- `handlers.Context().ListOrganizations`, `ListPermissions`, `ListOrgMembers`

### Session + permission
- `sdk.Middleware().RequirePermission("your.permission")`
- `handlers.Management().*` (admin CRUD)
- `handlers.Organizations().Create`, `Invite`, …

---

## Login / me response (organizations enabled)

Successful login and `GET /me` include:

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

When orgs are disabled, the `organization` block is omitted; authorization scopes to INSTALLATION.

---

## Context helpers (after RequireSession)

```go
aos.UserIDFromContext(ctx)
aos.ActiveResourceIDFromContext(ctx)    // business org UUID
aos.ActiveResourceIAMIDFromContext(ctx) // internal scope for Can()
```

---

## Authorization conventions

| Check | API |
|-------|-----|
| Route gate (implicit scope) | `Middleware().RequirePermission("code")` |
| Domain object check | `Authz().Can(ctx, AuthzInput{ResourceID: orgUUID, ...})` |
| Activate org | `Organizations().Activate(ctx, userID, token, orgUUID)` or `POST .../activate` |

`ResourceID` in `AuthzInput` accepts **business UUID or IAM id** (auto-resolved).

---

## Org-scoped roles (v0.4)

When `Organization.Enabled` is **true**:

- `Roles().Create` **requires** `OrganizationID` (business org UUID)
- `IsSystem: true` is rejected (bootstrap creates system roles internally)
- HTTP `POST /admin/roles` uses `organizationId` from body, or falls back to the **active session org**

When organizations are **disabled**:

- `OrganizationID` **must be omitted** (`ErrOrganizationScopeNotAllowed` otherwise)
- Roles are installation-scoped (`organization_id IS NULL`)

```go
roleID, err := sdk.Roles().Create(ctx, aos.CreateRoleInput{
    Name:           "Billing Admin",
    Description:    "...",
    OrganizationID: orgBusinessUUID, // required when orgs enabled
})
```

## Permissions (global catalog)

Permission codes (`payment.create`, etc.) are **always global** — register once at deploy via `Permissions().Register()`. Organization context is enforced on **roles and role assignments**, not on permission rows.

---

## Deprecated (avoid in new code)

| Deprecated | Use instead |
|------------|-------------|
| `sdk.Router()` | `sdk.Handler()` |
| `sdk.IAM()` | `sdk.Authz()` |
| `OrgIDFromContext` | `ActiveResourceIDFromContext` |
| `Auth().SwitchOrganization` | `SetActiveResource` / `Organizations().Activate` |
| `Session.OrgID` | `Session.ActiveResourceID` |
| `CreateOrgInput.TenantID` | Ignored |
| `CreateRoleInput.TenantID` | Ignored; use `OrganizationID` |
| `AuthzInput.TenantID` | Ignored for embedded installs |
| Flat `tenant_id` in requests | Not used in embedded mode |

---

## Internal (do not expose to end users)

- `iam_resources`, `resource_type`, recursive auth CTE details
- `user_sessions.active_resource_id` (IAM pk) — use business `organization_id` in your API
- Direct storage/repository packages

---

## Version target

| Version | Goal |
|---------|------|
| **v0.3** (current) | Org enrichment, org-scoped roles, activate, API doc |
| **v1.0** | Remove deprecated exports; frozen handler + programmatic surface |

See [`DEVELOPER.md`](./DEVELOPER.md) for integration examples.
