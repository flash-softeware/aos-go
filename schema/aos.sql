-- AOS canonical schema (full DDL)
-- See SCHEMA.md for architecture notes.
-- Apply in order. Requires PostgreSQL 14+.
--
-- No tenant table. No installations table.
-- Business hierarchy = iam_resources (app-defined types) + your app tables.
-- OAuth/domains/policies: app config or iam_resource-scoped plugins.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Meta ─────────────────────────────────────────────────────────────────────

CREATE TABLE schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Authentication ───────────────────────────────────────────────────────────

CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 VARCHAR(255) NOT NULL,
    username              VARCHAR(100),
    first_name            VARCHAR(100),
    middle_name           VARCHAR(100),
    last_name             VARCHAR(100),
    phone                 VARCHAR(30),
    avatar_url            TEXT,
    locale                VARCHAR(20) NOT NULL DEFAULT 'en',
    timezone              VARCHAR(100) NOT NULL DEFAULT 'UTC',
    email_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at     TIMESTAMPTZ,
    phone_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    phone_verified_at     TIMESTAMPTZ,
    status                VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('PENDING', 'ACTIVE', 'LOCKED', 'SUSPENDED', 'DELETED')),
    metadata              JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_login_at         TIMESTAMPTZ,
    last_login_ip         INET,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at            TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_users_email ON users (email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_username ON users (username) WHERE deleted_at IS NULL AND username IS NOT NULL;
CREATE INDEX idx_users_status ON users (status);

CREATE TABLE auth_accounts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            VARCHAR(30) NOT NULL
        CHECK (provider IN ('LOCAL', 'GOOGLE', 'MICROSOFT', 'APPLE', 'GITHUB', 'OIDC', 'SAML')),
    provider_user_id    VARCHAR(255),
    password_hash       TEXT,
    password_changed_at TIMESTAMPTZ,
    provider_metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_auth_accounts_user ON auth_accounts (user_id);

CREATE TABLE user_mfa (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type           VARCHAR(20) NOT NULL CHECK (type IN ('TOTP', 'SMS', 'EMAIL')),
    secret         TEXT,
    enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    verified       BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_codes JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, type)
);

CREATE INDEX idx_user_mfa_user ON user_mfa (user_id);

CREATE TABLE user_sessions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash   TEXT NOT NULL,
    active_resource_id   UUID,
    ip_address           INET,
    device_info          JSONB NOT NULL DEFAULT '{}'::jsonb,
    user_agent           TEXT,
    browser              VARCHAR(100),
    operating_system     VARCHAR(100),
    device_name          VARCHAR(255),
    device_id            VARCHAR(255),
    country              VARCHAR(100),
    city                 VARCHAR(100),
    expires_at           TIMESTAMPTZ NOT NULL,
    last_activity_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at           TIMESTAMPTZ,
    revoke_reason        VARCHAR(100),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user ON user_sessions (user_id);
CREATE INDEX idx_sessions_active ON user_sessions (user_id, revoked_at);
CREATE INDEX idx_sessions_expiry ON user_sessions (expires_at);
CREATE INDEX idx_sessions_token ON user_sessions (session_token_hash);

CREATE TABLE login_attempts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(255),
    user_id    UUID REFERENCES users(id),
    provider   VARCHAR(30),
    ip_address INET,
    user_agent TEXT,
    success    BOOLEAN,
    reason     VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_attempts_email ON login_attempts (email);
CREATE INDEX idx_login_attempts_ip ON login_attempts (ip_address);
CREATE INDEX idx_login_attempts_created ON login_attempts (created_at);

CREATE TABLE user_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        VARCHAR(30) NOT NULL
        CHECK (type IN (
            'EMAIL_VERIFICATION', 'PASSWORD_RESET', 'EMAIL_CHANGE', 'PHONE_VERIFICATION',
            'MAGIC_LINK', 'INVITATION', 'ACCOUNT_ACTIVATION', 'MFA_CHALLENGE'
        )),
    token_hash  TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_tokens_user ON user_tokens (user_id);
CREATE INDEX idx_user_tokens_type ON user_tokens (type);
CREATE INDEX idx_user_tokens_expires ON user_tokens (expires_at);
CREATE INDEX idx_user_tokens_active ON user_tokens (user_id, type) WHERE consumed_at IS NULL;

CREATE TABLE user_passkeys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    TEXT NOT NULL UNIQUE,
    public_key       TEXT NOT NULL,
    sign_count       BIGINT NOT NULL DEFAULT 0,
    transports       JSONB NOT NULL DEFAULT '[]'::jsonb,
    device_name      VARCHAR(255),
    aaguid           UUID,
    backed_up        BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_passkeys_user ON user_passkeys (user_id);
CREATE INDEX idx_user_passkeys_enabled ON user_passkeys (enabled);

CREATE TABLE passkey_challenges (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    challenge  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One embed per database; app may also store OAuth config in env / app tables.
CREATE TABLE oauth_providers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider      VARCHAR(30) NOT NULL
        CHECK (provider IN ('GOOGLE', 'GITHUB', 'MICROSOFT', 'APPLE', 'OIDC')),
    client_id     VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider)
);

-- ── Authorization ────────────────────────────────────────────────────────────
-- Hierarchy lives entirely in iam_resources. App defines resource_type strings.

CREATE TABLE iam_resources (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type      VARCHAR(50) NOT NULL,
    resource_id        UUID NOT NULL,
    parent_resource_id UUID REFERENCES iam_resources(id) ON DELETE CASCADE,
    name               VARCHAR(255),
    path               TEXT,
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (resource_type, resource_id)
);

CREATE INDEX idx_iam_resources_parent ON iam_resources (parent_resource_id);
CREATE INDEX idx_iam_resources_lookup ON iam_resources (resource_type, resource_id);

CREATE TABLE permissions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type VARCHAR(50) NOT NULL DEFAULT '*',
    action        VARCHAR(100) NOT NULL DEFAULT '*',
    code          VARCHAR(255) NOT NULL UNIQUE,
    description   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE roles (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID REFERENCES iam_resources(id) ON DELETE CASCADE,
    name                  VARCHAR(100) NOT NULL,
    description           TEXT,
    is_system             BOOLEAN NOT NULL DEFAULT FALSE,
    has_all_permissions   BOOLEAN NOT NULL DEFAULT FALSE,
    created_by            UUID REFERENCES users(id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_roles_system_name ON roles (name) WHERE organization_id IS NULL;
CREATE UNIQUE INDEX uq_roles_org_name ON roles (organization_id, name) WHERE organization_id IS NOT NULL;

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE memberships (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_type VARCHAR(50) NOT NULL,
    resource_id   UUID NOT NULL,
    status        VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'LEFT', 'REMOVED')),
    joined_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, resource_type, resource_id)
);

CREATE INDEX idx_memberships_user ON memberships (user_id);
CREATE INDEX idx_memberships_resource ON memberships (resource_type, resource_id);

CREATE TABLE role_assignments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id UUID NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    resource_id   UUID NOT NULL REFERENCES iam_resources(id) ON DELETE CASCADE,
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    effect        VARCHAR(10) NOT NULL DEFAULT 'ALLOW'
        CHECK (effect IN ('ALLOW', 'DENY')),
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (membership_id, resource_id, role_id)
);

CREATE INDEX idx_role_assignments_membership ON role_assignments (membership_id);
CREATE INDEX idx_role_assignments_resource ON role_assignments (resource_id);
CREATE INDEX idx_role_assignments_role ON role_assignments (role_id);

CREATE INDEX idx_role_assignments_active
    ON role_assignments (membership_id, resource_id)
    WHERE expires_at IS NULL;

CREATE TABLE invitations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id   UUID NOT NULL,
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    invited_by    UUID REFERENCES users(id),
    status        VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ACCEPTED', 'DECLINED', 'EXPIRED', 'REVOKED')),
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_invitations_pending
    ON invitations (email, resource_type, resource_id)
    WHERE status = 'PENDING';

-- ── Enterprise / admin plugins ─────────────────────────────────────────────

CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID REFERENCES users(id),
    action        VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id   UUID,
    result        VARCHAR(20) NOT NULL DEFAULT 'SUCCESS',
    details       JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created ON audit_logs (created_at);
CREATE INDEX idx_audit_logs_resource ON audit_logs (resource_type, resource_id);

CREATE TABLE api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    key_prefix   VARCHAR(16) NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user ON api_keys (user_id);

CREATE TABLE webhooks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url        TEXT NOT NULL,
    secret     TEXT NOT NULL,
    events     JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE webhook_deliveries (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id   UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type   VARCHAR(100) NOT NULL,
    payload      JSONB NOT NULL,
    status       VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempts     INT NOT NULL DEFAULT 0,
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries (webhook_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries (status);

CREATE TABLE security_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    iam_resource_id UUID REFERENCES iam_resources(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    policy_type     VARCHAR(50) NOT NULL,
    configuration   JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE domains (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain             VARCHAR(255) NOT NULL UNIQUE,
    verified           BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token TEXT,
    verified_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE resource_sso_connections (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    iam_resource_id         UUID NOT NULL REFERENCES iam_resources(id) ON DELETE CASCADE,
    provider                VARCHAR(30) NOT NULL,
    name                    VARCHAR(255) NOT NULL,
    enabled                 BOOLEAN NOT NULL DEFAULT FALSE,
    issuer_url              TEXT,
    metadata_url            TEXT,
    client_id               TEXT,
    client_secret_encrypted TEXT,
    certificate             TEXT,
    metadata                JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by              UUID REFERENCES users(id),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scim_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    iam_resource_id UUID NOT NULL REFERENCES iam_resources(id) ON DELETE CASCADE,
    provider        VARCHAR(50),
    token_hash      TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scim_sync_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID REFERENCES scim_connections(id) ON DELETE CASCADE,
    operation     VARCHAR(30) CHECK (operation IN ('CREATE', 'UPDATE', 'DELETE')),
    external_id   TEXT,
    status        VARCHAR(20),
    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE resource_network_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    iam_resource_id UUID NOT NULL REFERENCES iam_resources(id) ON DELETE CASCADE,
    cidr            VARCHAR(100) NOT NULL,
    description     TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE user_sessions
    ADD CONSTRAINT fk_session_active_resource
    FOREIGN KEY (active_resource_id) REFERENCES iam_resources(id) ON DELETE SET NULL;
