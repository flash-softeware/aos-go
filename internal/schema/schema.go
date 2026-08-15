package schema

const MultiTenantSchema = `


CREATE TABLE users (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    email VARCHAR(255) NOT NULL,

    username VARCHAR(100),

    first_name VARCHAR(100),

    middle_name VARCHAR(100),

    last_name VARCHAR(100),

    phone VARCHAR(30),

    avatar_url TEXT,

    locale VARCHAR(20)
        NOT NULL
        DEFAULT 'en',

    timezone VARCHAR(100)
        NOT NULL
        DEFAULT 'UTC',

    email_verified BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    email_verified_at TIMESTAMPTZ,

    phone_verified BOOLEAN
        NOT NULL
        DEFAULT FALSE,

    phone_verified_at TIMESTAMPTZ,

    status VARCHAR(30)
        NOT NULL
        DEFAULT 'ACTIVE'
        CHECK (
            status IN (
                'PENDING',
                'ACTIVE',
                'LOCKED',
                'SUSPENDED',
                'DELETED'
            )
        ),

    metadata JSONB
        NOT NULL
        DEFAULT '{}'::jsonb,

    last_login_at TIMESTAMPTZ,

    last_login_ip INET,

    failed_login_attempts INTEGER
        NOT NULL
        DEFAULT 0,

    locked_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_users_email ON users (email)
WHERE
    deleted_at IS NULL;

CREATE UNIQUE INDEX uq_users_username ON users (username)
WHERE
    deleted_at IS NULL;

CREATE INDEX idx_users_status ON users (status);

CREATE TABLE tenants (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    tenant_type VARCHAR(50) NOT NULL DEFAULT 'SAAS_PLATFORM',
    policies JSONB DEFAULT '{}',

    website TEXT,

    status VARCHAR(30)
        NOT NULL
        DEFAULT 'ACTIVE'
        CHECK (
            status IN (
                'ACTIVE',
                'PENDING',
                'SUSPENDED',
                'DELETED'
            )
        ),


    settings JSONB NOT NULL DEFAULT '{}'::jsonb,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_by UUID
        REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_tenants_slug ON tenants (slug)
WHERE
    deleted_at IS NULL;


CREATE TABLE organizations (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID
        NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    name VARCHAR(255) NOT NULL,

    slug VARCHAR(100) NOT NULL,

    description TEXT,

    status VARCHAR(30)
        NOT NULL
        DEFAULT 'ACTIVE'
        CHECK (
            status IN (
                'ACTIVE',
                'SUSPENDED',
                'DELETED'
            )
        ),

    settings JSONB NOT NULL DEFAULT '{}'::jsonb,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_by UUID
        REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    deleted_at TIMESTAMPTZ,

    UNIQUE (tenant_id, slug)
);


CREATE TABLE projects (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    organization_id UUID
        NOT NULL
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    name VARCHAR(255) NOT NULL,

    slug VARCHAR(100) NOT NULL,

    description TEXT,

    status VARCHAR(30)
        NOT NULL
        DEFAULT 'ACTIVE'
        CHECK (
            status IN (
                'ACTIVE',
                'ARCHIVED',
                'DELETED'
            )
        ),

    settings JSONB NOT NULL DEFAULT '{}'::jsonb,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_by UUID
        REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    deleted_at TIMESTAMPTZ,

    UNIQUE (organization_id, slug)
);




CREATE TABLE auth_accounts (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID
        NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    provider VARCHAR(30)
        NOT NULL
        CHECK (
            provider IN (
                'LOCAL',
                'GOOGLE',
                'MICROSOFT',
                'APPLE',
                'GITHUB',
                'OIDC',
                'SAML'
            )
        ),

    provider_user_id VARCHAR(255),

    password_hash TEXT,

    password_changed_at TIMESTAMPTZ,

    provider_metadata JSONB
        NOT NULL
        DEFAULT '{}'::jsonb,

    last_login_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_auth_accounts_user ON auth_accounts (user_id);

CREATE TABLE user_mfa (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL CHECK (
        type IN ('TOTP', 'SMS', 'EMAIL')
    ),
    secret TEXT,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_codes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    UNIQUE (user_id, type)
);

CREATE INDEX idx_user_mfa_user ON user_mfa (user_id);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants (id) ON DELETE CASCADE,
    session_token_hash TEXT NOT NULL,
    ip_address INET,
    device_info JSONB DEFAULT '{}'::jsonb,
    user_agent TEXT,
    browser VARCHAR(100),
    operating_system VARCHAR(100),
    device_name VARCHAR(255),
    device_id VARCHAR(255),
    country VARCHAR(100),
    city VARCHAR(100),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    revoked_at TIMESTAMPTZ,
    revoke_reason VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
);

CREATE INDEX idx_sessions_user ON user_sessions (user_id);

CREATE INDEX idx_sessions_active ON user_sessions (user_id, revoked_at);

CREATE INDEX idx_sessions_expiry ON user_sessions (expires_at);

CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    email VARCHAR(255),
    user_id UUID REFERENCES users (id),
    provider VARCHAR(30),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    reason VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

CREATE INDEX idx_login_attempts_email ON login_attempts (email);

CREATE INDEX idx_login_attempts_ip ON login_attempts (ip_address);

CREATE INDEX idx_login_attempts_created ON login_attempts (created_at);


CREATE TABLE user_tokens (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    type VARCHAR(30) NOT NULL
        CHECK (
            type IN (
                'EMAIL_VERIFICATION',
                'PASSWORD_RESET',
                'EMAIL_CHANGE',
                'PHONE_VERIFICATION',
                'MAGIC_LINK',
                'INVITATION',
                'ACCOUNT_ACTIVATION'
            )
        ),

    token_hash TEXT NOT NULL,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    expires_at TIMESTAMPTZ NOT NULL,

    consumed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_tokens_user ON user_tokens (user_id);

CREATE INDEX idx_user_tokens_type
ON user_tokens(type);

CREATE INDEX idx_user_tokens_expires ON user_tokens (expires_at);

CREATE INDEX idx_user_tokens_active
ON user_tokens(user_id, type)
WHERE consumed_at IS NULL;


CREATE TABLE user_passkeys (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    credential_id TEXT NOT NULL UNIQUE,

    public_key TEXT NOT NULL,

    sign_count BIGINT NOT NULL DEFAULT 0,

    transports JSONB
        NOT NULL
        DEFAULT '[]'::jsonb,

    device_name VARCHAR(255),

    aaguid UUID,

    backed_up BOOLEAN NOT NULL DEFAULT FALSE,

    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    last_used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_passkeys_user ON user_passkeys (user_id);

CREATE TABLE passkey_challenges (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_user_passkeys_enabled ON user_passkeys (enabled);
CREATE TABLE memberships (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,


    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,


    resource_type VARCHAR(20) NOT NULL
        CHECK (
            resource_type IN (
                'TENANT',
                'ORGANIZATION',
                'PROJECT'
            )
        ),


    resource_id UUID NOT NULL,


    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (
            status IN (
                'ACTIVE',
                'SUSPENDED',
                'LEFT',
                'REMOVED'
            )
        ),


    joined_at TIMESTAMPTZ DEFAULT NOW(),


    created_at TIMESTAMPTZ DEFAULT NOW(),

    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_memberships_user ON memberships (user_id);

CREATE INDEX idx_memberships_resource ON memberships (resource_type, resource_id);

CREATE TABLE iam_resources (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    resource_type VARCHAR(50)
        NOT NULL,

    resource_id UUID NOT NULL,

    parent_resource_id UUID
        REFERENCES iam_resources(id)
        ON DELETE CASCADE,

    name VARCHAR(255),

    path TEXT,

    metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    UNIQUE(resource_type, resource_id)
);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    tenant_id UUID REFERENCES tenants (id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    has_all_permissions BOOLEAN NOT NULL DEFAULT FALSE,
    created_by UUID REFERENCES users (id),
    created_at TIMESTAMPTZ DEFAULT NOW (),
    updated_at TIMESTAMPTZ DEFAULT NOW (),
    UNIQUE (tenant_id, name)
);

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    resource_type VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    code VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW ()
);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW (),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    membership_id UUID NOT NULL REFERENCES memberships (id) ON DELETE CASCADE,
    resource_id UUID NOT NULL REFERENCES iam_resources (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    effect VARCHAR(10) NOT NULL DEFAULT 'ALLOW' CHECK (effect IN ('ALLOW', 'DENY')),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW (),
    UNIQUE (
        membership_id,
        resource_id,
        role_id
    )
);

CREATE TABLE tenant_oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL CHECK (
        provider IN ('GOOGLE', 'GITHUB', 'MICROSOFT', 'APPLE', 'OIDC')
    ),
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, provider)
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant ON audit_logs (tenant_id);
CREATE INDEX idx_audit_logs_created ON audit_logs (created_at);

CREATE TABLE invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    resource_type VARCHAR(20) NOT NULL CHECK (resource_type IN ('TENANT', 'ORGANIZATION', 'PROJECT')),
    resource_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'DECLINED', 'EXPIRED', 'REVOKED')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_invitations_pending ON invitations (email, resource_id) WHERE status = 'PENDING';

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(50) NOT NULL,
    configuration JSONB NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verification_token TEXT,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(domain)
);

CREATE TABLE IF NOT EXISTS organization_sso_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL,
    name VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    issuer_url TEXT,
    metadata_url TEXT,
    client_id TEXT,
    client_secret_encrypted TEXT,
    certificate TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(50),
    token_hash TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    last_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_network_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cidr VARCHAR(100) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
`
