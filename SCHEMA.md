# AOS Database Schema

Canonical PostgreSQL schema for the AOS SDK. Applied by `aos.Migrate()`.

> **Full DDL:** [`schema/aos.sql`](./schema/aos.sql)

```bash
psql "$DATABASE_URL" -f schema/aos.sql
```

---

## Design principles

AOS provides **Auth + AuthZ primitives**. The application owns **business model and hierarchy**.

There is:

- **No `tenants` table** — merchant/org/department is not an AOS concept
- **No `installations` table** — not used for identity, authz, or business hierarchy
- **No automatic bootstrap** — no Owner, no `*`, no first admin in the SDK

```text
AOS                           Application
─────────────────────         ─────────────────────────
users                         merchants, hospitals, …
sessions                      platform admin concept
password / OAuth / MFA        role names (Merchant Owner, Doctor, …)
iam_resources                 business tables + UUIDs
memberships                   onboarding flows
roles / permissions           POST /setup
Can()
```

---

## Where everything lives

| Concern | Owner |
|---------|--------|
| Who is this user? | AOS `users`, `auth_accounts`, `user_sessions` |
| What can they do? | AOS `permissions`, `roles`, `memberships`, `Can()` |
| What is a merchant / org / dept? | **Your app** + `iam_resources.resource_type` |
| Platform admin, first founder | **Your app** (`POST /setup`) |
| OAuth client IDs, app settings | **Your app** (env, config, or app tables) |
| Product domains | **Your app**, or AOS `domains` plugin (global per DB) |

---

## Authorization hierarchy

All business structure flows through **`iam_resources`**:

```text
iam_resources (type=platform, id=…)        ← PayGate admin side (app creates)
  ├── iam_resources (type=merchant, id=m_1)
  │     └── iam_resources (type=invoice, id=…)
  └── iam_resources (type=merchant, id=m_2)
```

Another app:

```text
iam_resources (type=hospital, id=…)
  ├── iam_resources (type=department, id=…)
  └── iam_resources (type=department, id=…)
```

AOS does not interpret `resource_type` — it is an opaque string from your app.

**Bridge:** `iam_resources.resource_id` = your business table primary key (no FK).

```text
permissions → roles → role_permissions
                ↓
         role_assignments ← memberships ← users
                ↓
          iam_resources (parent_resource_id = hierarchy)
```

```text
Can(user, resource_id, permission)
  → walk parent chain
  → find membership + role on ancestor
  → DENY beats ALLOW
```

---

## Why no `installations`

If a table is not used to:

- identify the business tenant
- create an owner
- define business roles or permissions
- enforce authorization
- represent merchants

…then it adds no value. Config (OAuth, domains, policies) belongs in **your application** or in **optional AOS plugin tables** scoped globally (one embed per database) or per `iam_resource`.

---

## Table groups

### Meta

| Table | Purpose |
|-------|---------|
| `schema_migrations` | Migration tracking |

### Authentication

| Table | Purpose |
|-------|---------|
| `users` | Identity profile |
| `auth_accounts` | Password, OAuth, SAML |
| `user_mfa` | TOTP / SMS / EMAIL |
| `user_sessions` | Sessions + `active_resource_id` |
| `login_attempts` | Brute-force tracking |
| `user_tokens` | Verify email, reset password, invite |
| `user_passkeys` | WebAuthn |
| `passkey_challenges` | WebAuthn ceremony |
| `oauth_providers` | Optional; one row per provider per DB embed |

### Authorization

| Table | Purpose |
|-------|---------|
| `iam_resources` | Generic nodes; app-defined `resource_type` |
| `permissions` | App-registered codes |
| `roles` | App-defined names; `UNIQUE(name)` per embed |
| `role_permissions` | Role → permission |
| `memberships` | User ↔ resource (`resource_type` + `resource_id`) |
| `role_assignments` | Membership + IAM node + role |
| `invitations` | Invite user to resource with role |

### Enterprise plugins (optional)

| Table | Purpose |
|-------|---------|
| `audit_logs` | Security audit |
| `api_keys` | API keys (user-scoped) |
| `webhooks` / `webhook_deliveries` | Platform webhooks |
| `security_policies` | Per-resource or global policies |
| `domains` | Verified domains (global per embed) |
| `resource_sso_connections` | SSO on any IAM resource |
| `scim_connections` / `scim_sync_logs` | SCIM |
| `resource_network_rules` | IP allowlists per resource |

---

## PayGate example (application-owned)

```text
1. aos migrate                    → empty AOS tables
2. POST /setup (your app)         → SignUp + platform resource + Platform Owner role
3. merchant signup (your app)     → merchants row + iam_resources(type=merchant)
4. assign membership + role       → Memberships().Add + AssignRole
5. Can(user, merchant_id, perm)   → authorization
```

AOS after migrate alone:

```text
(empty authn/authz tables — no users, no roles, no resources)
```

---

## Table index

| Table | Required |
|-------|----------|
| `schema_migrations` | yes |
| `users` | yes |
| `auth_accounts` | yes |
| `user_mfa` | yes |
| `user_sessions` | yes |
| `login_attempts` | yes |
| `user_tokens` | yes |
| `user_passkeys` | yes |
| `passkey_challenges` | yes |
| `oauth_providers` | optional |
| `iam_resources` | yes |
| `permissions` | yes |
| `roles` | yes |
| `role_permissions` | yes |
| `memberships` | yes |
| `role_assignments` | yes |
| `invitations` | yes |
| `audit_logs` | optional |
| `api_keys` | optional |
| `webhooks` | optional |
| `webhook_deliveries` | optional |
| `security_policies` | optional |
| `domains` | optional |
| `resource_sso_connections` | optional |
| `scim_connections` | optional |
| `scim_sync_logs` | optional |
| `resource_network_rules` | optional |

**Removed from canonical schema:** `tenants`, `installations`, `organizations`, `projects`.

---

## SDK v0.1.x delta

| Canonical | v0.1.x today |
|-----------|--------------|
| No `installations` / `tenants` | `tenants` + bootstrap Owner |
| `iam_resources` only hierarchy | `tenant_id` / `installation_id` FKs |
| `roles.name` UNIQUE globally | scoped by tenant |
| `memberships` any `resource_type` | CHECK enum |
| No `Bootstrap()` | `aos.Bootstrap()` seeds Owner + `*` |

---

## Related

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — instantiation, storage, providers, plugins
- [`SDK.md`](./SDK.md) — Better Auth-style quick start
- [`schema/aos.sql`](./schema/aos.sql) — copy-paste DDL
- [`final.md`](./final.md) — original plugin design notes
