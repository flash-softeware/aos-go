# AOS Architecture

Canonical design: **modular inside, simple outside** (Better Auth-style DX).

Related: [`SCHEMA.md`](./SCHEMA.md) · [`SDK.md`](./SDK.md) · [`schema/aos.sql`](./schema/aos.sql)

---

## Principles

1. **AOS owns Auth + AuthZ primitives** — not business model, not bootstrap Owner, no tenants/installations.
2. **Application owns business IAM** — merchants, platform admin, role names, `/setup`.
3. **`aos.New(Config{DatabaseURL})`** — sensible defaults; advanced config when needed.
4. **Four internal concepts** — Storage, Providers, Auth/AuthZ core, Plugins — hidden from most developers.

---

## Developer experience (target)

### Simple (default)

```go
aos, err := aos.New(ctx, aos.Config{
    DatabaseURL: os.Getenv("DATABASE_URL"),
})
if err != nil {
    log.Fatal(err)
}

if err := aos.Migrate(ctx); err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/auth/", aos.Handler())
mux.Handle("/me", aos.RequireAuth(http.HandlerFunc(meHandler)))

log.Fatal(http.ListenAndServe(":8080", mux))
```

### Convenient API (top-level)

```go
out, err := aos.SignUp(ctx, aos.SignUpInput{Email, Password})
token, err := aos.SignIn(ctx, email, password)
err = aos.SignOut(ctx, token)
sess, err := aos.Session(ctx, token)

allowed, err := aos.Can(ctx, userID, merchantID, "payment.refund")
```

### Domain API (advanced / explicit)

```go
aos.Auth().SignUp(...)
aos.Authz().Can(...)
aos.Authz().Resources().Create(...)
aos.Authz().Roles().Grant(...)
aos.Authz().Memberships().Add(...)
```

Both surfaces call the same core.

---

## What `aos.New()` does — and does not

```text
aos.New(Config{ DatabaseURL })
    │
    ├── storage   → postgres adapter (default)
    ├── providers → password (default)
    ├── authz     → rbac engine (always on)
    ├── plugins   → none (default)
    └── events    → in-process bus
    │
    ├── ✅ connect DB
    ├── ✅ wire Auth + AuthZ
    │
    ├── ❌ create owner
    ├── ❌ create merchant
    ├── ❌ create roles / permissions
    └── ❌ create IAM hierarchy
```

Business setup stays in **your application** (`POST /setup`, merchant signup, etc.).

---

## Advanced configuration

### Explicit storage (recommended for advanced apps)

```go
import (
    aos "github.com/Esubalew-Sintie/aos-auth-go"
    "github.com/Esubalew-Sintie/aos-auth-go/storage"
)

store, err := storage.NewPostgres(ctx, os.Getenv("DATABASE_URL"))
if err != nil {
    log.Fatal(err)
}

sdk, err := aos.New(ctx, aos.Config{
    Storage: store,
})
```

| API | When to use |
|-----|-------------|
| `storage.NewPostgres(ctx, dbURL)` | Explicit connect — production, custom pool settings later |
| `storage.NewPostgresFromPool(pool)` | Shared `pgxpool`, tests with existing pool |
| `aos.Config{DatabaseURL}` | Simple path — same as `NewPostgres` internally |

`Migrate()` uses `store.DB()` — the adapter must expose the underlying pool.

### Full advanced config (target)

```go
store, _ := storage.NewPostgres(ctx, os.Getenv("DATABASE_URL"))

sdk, err := aos.New(ctx, aos.Config{
    Storage:   store,
    RedisAddr: os.Getenv("REDIS_ADDR"),

    Auth: aos.AuthConfig{
        Password: true,
        OAuth: []aos.OAuthProviderConfig{
            {
                Name:         "google",
                ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
                ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            },
        },
        Passkey: &aos.PasskeyConfig{
            RPID:    "paygate.com",
            Origins: []string{"https://app.paygate.com"},
        },
    },

    Plugins: []aos.Plugin{
        audit.New(),
        ratelimit.New(redisAddr),
    },
})
```

| Level | Config |
|-------|--------|
| Simple | `DatabaseURL` only |
| Explicit storage | `storage.NewPostgres` + `Config{Storage}` |
| Auth extras | `Auth.OAuth`, `Auth.Passkey`, `Auth.MFA` (target) |
| Ops | `Plugins: audit, ratelimit, webhooks` (target) |

---

## Internal wiring (what defaults expand to)

```go
// Conceptual — inside aos.New()
var store storage.Repository
if cfg.Storage != nil {
    store = cfg.Storage
} else {
    store, _ = storage.NewPostgres(ctx, cfg.DatabaseURL)
}

providers := []Provider{password.New(store)}
authz := rbac.New(store)

return &AOS{storage: store, auth: ..., authz: authz}
```

```text
                    aos.New()
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
     Storage        Providers       Plugins
   (postgres)     (password,…)    (audit,…)
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                ┌─────────────┐
                │     AOS     │
                ├─────────────┤
                │    Auth     │  ← core
                │    AuthZ    │  ← core
                │   Events    │
                └─────────────┘
                       │
              YOUR APPLICATION
         (business tables + business IAM)
```

---

## Module layout (target)

```text
aos/
├── aos.go                 # New, Migrate, Handler, RequireAuth, SignUp, Can, …
│
├── auth/                  # CORE AuthN
│   ├── user.go
│   ├── session.go
│   ├── password.go
│   ├── oauth.go
│   ├── passkey.go
│   └── mfa.go
│
├── authz/                 # CORE AuthZ
│   ├── resource.go        → iam_resources
│   ├── membership.go      → memberships
│   ├── role.go            → roles, role_permissions
│   ├── permission.go      → permissions
│   ├── assignment.go      → role_assignments
│   ├── invitation.go      → invitations
│   └── evaluator.go       → Can()
│
├── storage/               # INFRASTRUCTURE — strategic design
│   ├── repositories.go   # Storage facade + sub-repository interfaces (contract)
│   ├── STORAGE.md         # multi-DB strategy (postgres, mysql, mongo, …)
│   ├── storage.go         # v0.1.x legacy NewPostgres → Repository
│   ├── postgres/          # target: postgres.New(ctx, url)
│   ├── mysql/             # target
│   ├── mongodb/           # target
│   └── memory/            # target — tests
│
├── providers/             # AUTH METHODS (plug into auth/)
│   ├── password/
│   ├── oauth2/
│   ├── passkey/
│   └── magiclink/
│
└── plugins/               # OPTIONAL
    ├── audit/             → audit_logs
    ├── ratelimit/         → redis, hooks
    ├── webhooks/          → webhooks, webhook_deliveries
    ├── apikey/            → api_keys
    ├── security/          → security_policies
    ├── domains/           → domains
    ├── sso/               → resource_sso_connections
    └── scim/              → scim_connections
```

---

## Storage — strategic design (multi-database)

**Yes — use the Strategy pattern.** Auth and AuthZ talk only to `storage.Store`. Drivers implement sub-repositories.

```text
Auth / AuthZ  →  storage.Store  →  postgres | mysql | oracle | mongodb | memory
```

**Don't** use one giant `Repository` with 80+ methods (current v0.1.x legacy).  
**Do** split into `UserRepository`, `SessionRepository`, `RoleRepository`, … — see [`storage/repositories.go`](./storage/repositories.go).

Full design: [`storage/STORAGE.md`](./storage/STORAGE.md)

### Developer API (target — same for every DB)

```go
store, _ := postgres.New(ctx, databaseURL)   // or mysql.New, mongodb.New
sdk, _ := aos.New(ctx, aos.Config{Storage: store})
_ = sdk.Migrate(ctx)
```

### Why we weren't there yet

| Legacy (now) | Strategic (target) |
|--------------|-------------------|
| `internal/storage.Repository` — monolith | `storage.Store` — facade |
| Auth imports entire repo | Auth uses `store.Users()`, `store.Sessions()` |
| Postgres-only | Same contract for MySQL, Oracle, Mongo |
| `storage.NewPostgres` returns `Repository` | `postgres.New` returns `Store` |

v0.1.x keeps legacy `Repository` working. Contracts in `repositories.go` define v0.2 direction.

### Explicit storage today

Import explicitly when you need control over the database connection:

```go
import "github.com/Esubalew-Sintie/aos-auth-go/storage"

store, err := storage.NewPostgres(ctx, os.Getenv("DATABASE_URL"))
sdk, err := aos.New(ctx, aos.Config{Storage: store})
```

**Adapter interface** — one backend implements all table access (`storage.Repository`).

| Domain | Tables | Required |
|--------|--------|----------|
| Meta | `schema_migrations` | yes |
| AuthN | `users`, `auth_accounts`, `user_sessions`, `user_mfa`, `user_tokens`, `user_passkeys`, `passkey_challenges`, `login_attempts` | yes |
| AuthZ | `iam_resources`, `permissions`, `roles`, `role_permissions`, `memberships`, `role_assignments`, `invitations` | yes |
| OAuth config | `oauth_providers` | optional (or app env) |
| Plugins | `audit_logs`, `api_keys`, `webhooks`, … | optional |

**Not in AOS storage:** merchants, payments, platform config — your app migrations.

Default: **Postgres** via `DatabaseURL`.  
Optional: **Redis** for session cache and ratelimit plugin.

---

## Providers (AuthN methods)

Providers authenticate only. They return **user + session**. No roles.

| Provider | Default | Tables |
|----------|---------|--------|
| **password** | ✅ on | `auth_accounts` (LOCAL), `user_sessions` |
| **oauth** | off until configured | `auth_accounts`, `oauth_providers` |
| **passkey** | off until configured | `user_passkeys`, `passkey_challenges` |
| **mfa** | off until enabled | `user_mfa`, `user_tokens` |
| **magiclink** | future | `user_tokens` |

Routes mounted under `/auth/` via `aos.Handler()`.

---

## Plugins (optional)

Plugins add tables, hooks, routes. They do **not** model merchants or tenants.

| Plugin | Purpose | Storage |
|--------|---------|---------|
| **audit** | Sign-in / authz audit trail | `audit_logs` |
| **ratelimit** | Login brute-force limits | Redis |
| **webhooks** | AOS event delivery | `webhooks` |
| **apikey** | Bearer token auth | `api_keys` |
| **security** | Password/MFA policies | `security_policies` |
| **domains** | Domain verification | `domains` |
| **sso** | SAML/OIDC per resource | `resource_sso_connections` |
| **scim** | User provisioning | `scim_connections` |
| **network** | IP allowlists | `resource_network_rules` |

Enterprise plugins attach to **`iam_resource_id`** (a node your app created).

### Not a plugin

| Removed concept | Replacement |
|-----------------|-------------|
| Tenancy / tenant table | App + `iam_resources` hierarchy |
| Bootstrap Owner | App `POST /setup` |
| organizations helper | App tables + `iam_resources` |

---

## Auth vs AuthZ (always core)

| | AuthN | AuthZ |
|---|-------|-------|
| Question | Who is this person? | What can they do? |
| API | `SignUp`, `SignIn`, `Session` | `Can`, `Resources`, `Roles`, `Memberships` |
| Tables | users, sessions, credentials | iam_resources, roles, memberships |

Never merge. Auth never assigns business roles on signup.

---

## HTTP surface

| Export | Purpose |
|--------|---------|
| `aos.Handler()` | Mount at `/auth/` — login, signup, OAuth callbacks, MFA |
| `aos.RequireAuth(h)` | Middleware — valid session required |
| `aos.RequirePermission(code)(h)` | Middleware — `Can()` on active resource |

---

## Application-owned setup (PayGate)

```text
aos migrate              → empty AOS tables

POST /setup (your app)
  SignUp                   → user + session
  Resources().Create       → iam_resources type=platform
  Permissions().Register   → platform.admin, payment.refund, …
  Roles().Create + Grant   → Platform Owner
  Memberships().Add        → founder → platform resource

POST /merchants/signup (your app)
  INSERT merchants
  Resources().Create       → type=merchant
  SignUp + AssignRole      → merchant owner
```

---

## CLI (target)

| Command | Action |
|---------|--------|
| `aos migrate` | Run AOS schema only |
| `aos init` | Scaffold Go/React project |
| `aos generate setup` | Generate editable app setup handler (not core bootstrap) |

---

## v0.1.x → target migration

| v0.1.x | Target |
|--------|--------|
| `aos.Bootstrap()` | Remove — app `/setup` |
| `tenants` table | Remove — `iam_resources` only |
| `aos.Router()` | `aos.Handler()` |
| `TenantID` in SignUp | Remove — global users per embed |
| Only `Auth()` / `Authz()` | + top-level `SignUp`, `Can`, … |

---

## Related

- [`SDK.md`](./SDK.md) — developer quick start
- [`SCHEMA.md`](./SCHEMA.md) — database schema
- [`final.md`](./final.md) — original plugin design notes
