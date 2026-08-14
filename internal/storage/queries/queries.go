package queries

// IAM Queries
const (
	CheckPermission = `
		WITH RECURSIVE resource_tree AS (
			SELECT id, parent_resource_id, resource_id as raw_resource_id
			FROM iam_resources
			WHERE resource_id = $2
			
			UNION ALL
			
			SELECT ir.id, ir.parent_resource_id, ir.resource_id as raw_resource_id
			FROM iam_resources ir
			INNER JOIN resource_tree rt ON rt.parent_resource_id = ir.id
		),
		matched_assignments AS (
			SELECT ra.effect
			FROM memberships m
			JOIN role_assignments ra ON ra.membership_id = m.id
			JOIN roles r ON r.id = ra.role_id
			JOIN role_permissions rp ON rp.role_id = r.id
			JOIN permissions p ON p.id = rp.permission_id
			WHERE m.user_id = $1
			  AND m.status = 'ACTIVE'
			  AND m.resource_id IN (SELECT raw_resource_id FROM resource_tree)
			  AND ra.resource_id IN (SELECT id FROM resource_tree)
			  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
			  AND (
				  p.code = $3 
				  OR p.code = split_part($3, '.', 1) || '.*' 
				  OR p.code = split_part($3, '.', 1) || '.' || split_part($3, '.', 2) || '.*'
				  OR p.code = '*'
			  )
		)
		SELECT 
			CASE 
				WHEN EXISTS (SELECT 1 FROM matched_assignments WHERE effect = 'DENY') THEN false
				WHEN EXISTS (SELECT 1 FROM matched_assignments WHERE effect = 'ALLOW') THEN true
				ELSE false
			END as allowed;
	`
	
	InsertAuditLog = `INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, result, details, ip_address) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	GetAuditLogs = `
		SELECT id, tenant_id, user_id, action, resource_type, resource_id, result, details, ip_address, created_at
		FROM audit_logs
		WHERE ($1::uuid IS NULL OR tenant_id = $1)
		  AND ($2 = '' OR action ILIKE '%' || $2 || '%')
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`

	ListUserSessions = `
		SELECT id, ip_address, device_info, created_at, expires_at
		FROM user_sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
	`
	RevokeUserSession = `
		UPDATE user_sessions SET revoked_at = NOW(), revoke_reason = 'user_revoked'
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
	`
	RevokeAllUserSessions = `
		UPDATE user_sessions SET revoked_at = NOW(), revoke_reason = 'user_revoked'
		WHERE user_id = $1 AND revoked_at IS NULL AND ($2 = '' OR session_token_hash != $2)
	`
	GetSessionTokenHash = `SELECT session_token_hash FROM user_sessions WHERE id = $1 AND user_id = $2`

	GetApiKeys = `
		SELECT id, name, key_prefix, scopes, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE ($1::uuid IS NULL OR tenant_id = $1) AND revoked_at IS NULL
		ORDER BY created_at DESC
	`
	InsertApiKey = `
		INSERT INTO api_keys (tenant_id, user_id, name, key_prefix, key_hash, scopes)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, key_prefix, scopes, created_at
	`
	RevokeApiKey = `UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`

	GetWebhooks = `
		SELECT id, url, events, enabled, created_at, updated_at
		FROM webhooks
		WHERE ($1::uuid IS NULL OR tenant_id = $1)
		ORDER BY created_at DESC
	`
	InsertWebhook = `
		INSERT INTO webhooks (tenant_id, url, secret, events, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, url, events, enabled, created_at
	`
	DeleteWebhook = `DELETE FROM webhooks WHERE id = $1`

	GetSecurityPolicies = `
		SELECT id, tenant_id, organization_id, name, policy_type, configuration, enabled, created_at
		FROM security_policies
		WHERE ($1::uuid IS NULL OR tenant_id = $1)
		  AND ($2::uuid IS NULL OR organization_id = $2 OR organization_id IS NULL)
		ORDER BY created_at DESC
	`
	InsertSecurityPolicy = `
		INSERT INTO security_policies (tenant_id, organization_id, name, policy_type, configuration, enabled)
		VALUES ($1, $2, $3, $4, $5, TRUE)
		RETURNING id, name, policy_type, configuration, enabled, created_at
	`
	DeleteSecurityPolicy = `DELETE FROM security_policies WHERE id = $1`

	GetTenantDomains = `
		SELECT id, tenant_id, domain, verified, verified_at, created_at
		FROM tenant_domains WHERE tenant_id = $1 ORDER BY created_at DESC
	`
	InsertTenantDomain = `
		INSERT INTO tenant_domains (tenant_id, domain, verified, verification_token)
		VALUES ($1, $2, FALSE, $3)
		ON CONFLICT (domain) DO UPDATE SET verification_token = EXCLUDED.verification_token, verified = FALSE
		RETURNING id, tenant_id, domain, verified, verification_token, created_at
	`
	VerifyTenantDomain = `UPDATE tenant_domains SET verified = TRUE, verified_at = NOW() WHERE id = $1 RETURNING id, domain, verified, verified_at`
	DeleteTenantDomain = `DELETE FROM tenant_domains WHERE id = $1`

	GetSsoConnections = `
		SELECT id, organization_id, provider, name, enabled, issuer_url, metadata_url, client_id, created_at
		FROM organization_sso_connections WHERE organization_id = $1 ORDER BY created_at DESC
	`
	InsertSsoConnection = `
		INSERT INTO organization_sso_connections (organization_id, provider, name, enabled, issuer_url, client_id, created_by)
		VALUES ($1, $2, $3, FALSE, $4, $5, $6)
		RETURNING id, organization_id, provider, name, enabled, issuer_url, created_at
	`
	UpdateSsoConnection = `UPDATE organization_sso_connections SET enabled = $1, updated_at = NOW() WHERE id = $2`
	DeleteSsoConnection = `DELETE FROM organization_sso_connections WHERE id = $1`

	GetScimConnections = `
		SELECT id, organization_id, provider, enabled, last_sync_at, created_at
		FROM scim_connections WHERE organization_id = $1 ORDER BY created_at DESC
	`
	InsertScimConnection = `
		INSERT INTO scim_connections (organization_id, provider, token_hash, enabled)
		VALUES ($1, $2, $3, TRUE)
		RETURNING id, organization_id, provider, enabled, created_at
	`
	RevokeScimConnection = `UPDATE scim_connections SET enabled = FALSE WHERE id = $1`

	GetMfaStatusRow = `SELECT enabled, verified FROM user_mfa WHERE user_id = $1 AND type = 'TOTP' LIMIT 1`
	UpsertMfaSecret = `
		INSERT INTO user_mfa (user_id, type, secret, enabled, verified)
		VALUES ($1, 'TOTP', $2, FALSE, FALSE)
		ON CONFLICT (user_id, type) DO UPDATE
		SET secret = EXCLUDED.secret, enabled = FALSE, verified = FALSE, updated_at = NOW()`
	GetMfaSecret = `SELECT secret FROM user_mfa WHERE user_id = $1 AND type = 'TOTP'`
	EnableMfa = `
		UPDATE user_mfa SET enabled = TRUE, verified = TRUE, recovery_codes = $2, updated_at = NOW()
		WHERE user_id = $1 AND type = 'TOTP'`
	GetMfaWithRecovery = `
		SELECT secret, recovery_codes FROM user_mfa
		WHERE user_id = $1 AND type = 'TOTP' AND enabled = TRUE`
	UpdateMfaRecoveryCodes = `UPDATE user_mfa SET recovery_codes = $2 WHERE user_id = $1 AND type = 'TOTP'`
	DisableMfa = `
		UPDATE user_mfa SET enabled = FALSE, verified = FALSE, secret = NULL, recovery_codes = NULL, updated_at = NOW()
		WHERE user_id = $1 AND type = 'TOTP'`
	InsertMfaChallenge = `
		INSERT INTO user_tokens (user_id, type, token_hash, metadata, expires_at)
		VALUES ($1, 'MFA_CHALLENGE', $2, '{}'::jsonb, $3)`
	ConsumeMfaChallenge = `
		UPDATE user_tokens SET consumed_at = NOW()
		WHERE token_hash = $1 AND type = 'MFA_CHALLENGE' AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING user_id`

	GetNetworkRules = `
		SELECT id, organization_id, cidr, description, enabled, created_at
		FROM organization_network_rules WHERE organization_id = $1 ORDER BY created_at DESC
	`
	InsertNetworkRule = `
		INSERT INTO organization_network_rules (organization_id, cidr, description, enabled)
		VALUES ($1, $2, $3, TRUE) RETURNING id, cidr, description, enabled, created_at
	`
	DeleteNetworkRule = `DELETE FROM organization_network_rules WHERE id = $1`

	// Admin GET Queries
	GetUsers = `SELECT id, email, first_name, last_name FROM users`
	GetRoles = `SELECT id, name, description FROM roles`
	GetOrganizations = `SELECT id, name, slug FROM organizations`
	GetPermissions     = `SELECT id, resource_type, action, code, COALESCE(description, '') as description FROM permissions ORDER BY resource_type, action`
	GetRolePermissions = `SELECT permission_id FROM role_permissions WHERE role_id = $1`
	DeleteRolePerms    = `DELETE FROM role_permissions WHERE role_id = $1`
	GetMemberships = `SELECT id, user_id, resource_type, resource_id FROM memberships`
	GetTenants = `SELECT id, name, slug FROM tenants`
	GetOAuthProviders = `SELECT id::text, provider, client_id FROM tenant_oauth_providers WHERE ($1 = '' OR tenant_id::text = $1) ORDER BY provider`

	GetUserOrganizations = `
		SELECT o.id, o.name, o.slug, m.id AS membership_id,
		       COALESCE(r.id::text, '') AS role_id, COALESCE(r.name, '') AS role_name
		FROM memberships m
		JOIN organizations o ON o.id = m.resource_id
		LEFT JOIN role_assignments ra ON ra.membership_id = m.id
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		LEFT JOIN roles r ON r.id = ra.role_id
		WHERE m.user_id = $1 AND m.resource_type = 'ORGANIZATION' AND m.status = 'ACTIVE'
		ORDER BY o.name`

	UserHasOrgMembership = `
		SELECT EXISTS(
			SELECT 1 FROM memberships
			WHERE user_id = $1 AND resource_type = 'ORGANIZATION' AND resource_id = $2 AND status = 'ACTIVE'
		)`

	GetOrgMembers = `
		SELECT u.id AS user_id, u.email, u.first_name, u.last_name, COALESCE(r.name, '') AS role_name
		FROM memberships m
		JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
		LEFT JOIN role_assignments ra ON ra.membership_id = m.id
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		LEFT JOIN roles r ON r.id = ra.role_id
		WHERE m.resource_type = 'ORGANIZATION' AND m.resource_id = $1 AND m.status = 'ACTIVE'
		ORDER BY u.email`

	GetUserPermissionCodes = `
		SELECT DISTINCT p.code
		FROM memberships m
		JOIN role_assignments ra ON ra.membership_id = m.id AND ra.effect = 'ALLOW'
		JOIN role_permissions rp ON rp.role_id = ra.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE m.user_id = $1 AND m.resource_id = $2 AND m.status = 'ACTIVE'
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		ORDER BY p.code`
)

// User Queries
const (
	InsertUser           = `INSERT INTO users (email, first_name, last_name, status) VALUES ($1, $2, $3, 'ACTIVE') RETURNING id`
	InsertUserWithStatus = `INSERT INTO users (email, first_name, last_name, status) VALUES ($1, $2, $3, $4) RETURNING id`
	GetUserIDByEmail     = `SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL`
	InsertUserToken      = `INSERT INTO user_tokens (user_id, type, token_hash, metadata, expires_at) VALUES ($1, $2, $3, $4, $5)`
	ConsumeUserToken     = `
		UPDATE user_tokens SET consumed_at = NOW()
		WHERE token_hash = $1 AND type = $2 AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING user_id`
	ConsumeUserTokenWithMeta = `
		UPDATE user_tokens SET consumed_at = NOW()
		WHERE token_hash = $1 AND type = $2 AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING user_id, metadata`
	UpdateLocalPassword = `
		UPDATE auth_accounts SET password_hash = $1, password_changed_at = NOW()
		WHERE user_id = $2 AND provider = 'LOCAL'`
	InsertLocalAuthAccount = `INSERT INTO auth_accounts (user_id, provider, password_hash) VALUES ($1, 'LOCAL', $2)`
	ActivateUserEmail = `
		UPDATE users SET status = 'ACTIVE', email_verified_at = NOW(), updated_at = NOW()
		WHERE id = $1`
	CompleteInvitationUser = `
		UPDATE users SET first_name = $1, last_name = $2, status = 'ACTIVE', email_verified_at = NOW(), updated_at = NOW()
		WHERE id = $3`
	ActivatePendingMemberships = `
		UPDATE memberships SET status = 'ACTIVE', updated_at = NOW()
		WHERE user_id = $1 AND status = 'PENDING'`
	InsertPendingOrgMember = `
		INSERT INTO memberships (tenant_id, user_id, resource_type, resource_id, status)
		VALUES ($1, $2, 'ORGANIZATION', $3, 'PENDING') RETURNING id`
	GetOAuthProviderCreds = `
		SELECT client_id, client_secret FROM tenant_oauth_providers
		WHERE tenant_id = $1 AND provider = $2 LIMIT 1`
	GetAuthAccountByProvider = `
		SELECT user_id FROM auth_accounts WHERE provider = $1 AND provider_user_id = $2 LIMIT 1`
	InsertOAuthAccount = `
		INSERT INTO auth_accounts (user_id, provider, provider_user_id) VALUES ($1, $2, $3)`
	InsertAuthAccount    = `INSERT INTO auth_accounts (user_id, provider, password_hash) VALUES ($1, 'LOCAL', $2)`
	GetRoleByName        = `SELECT id FROM roles WHERE tenant_id = $1 AND name = $2 LIMIT 1`
	InsertMembership     = `INSERT INTO memberships (tenant_id, user_id, resource_type, resource_id, status) VALUES ($1, $2, 'TENANT', $1, 'ACTIVE') RETURNING id`
	GetIAMResource       = `SELECT id FROM iam_resources WHERE resource_id=$1 AND resource_type=$2`
	InsertRoleAssignment = `INSERT INTO role_assignments (membership_id, resource_id, role_id) VALUES ($1, $2, $3)`
	InsertSession = `INSERT INTO user_sessions (user_id, tenant_id, organization_id, role_id, active_resource_id, session_token_hash, expires_at) VALUES ($1, NULLIF($2,'')::uuid, NULLIF($3,'')::uuid, NULLIF($4,'')::uuid, NULLIF($3,'')::uuid, $5, $6)`
	GetUserByID          = `SELECT id, email, first_name, last_name, status FROM users WHERE id = $1 AND deleted_at IS NULL`
)

// Auth Queries
const (
	GetUserAuth = `
		SELECT u.id, a.password_hash 
		FROM users u 
		JOIN auth_accounts a ON a.user_id = u.id 
		WHERE u.email = $1 AND a.provider = 'LOCAL'
	`
	GetUserDefaultTenant = `SELECT tenant_id FROM memberships WHERE user_id = $1 AND status = 'ACTIVE' LIMIT 1`
	ValidateSessionToken = `SELECT user_id FROM user_sessions WHERE session_token_hash = $1 AND expires_at > NOW() AND revoked_at IS NULL`
	GetSessionByToken = `SELECT user_id, COALESCE(tenant_id::text, ''), COALESCE(COALESCE(active_resource_id, organization_id)::text, ''), COALESCE(role_id::text, '') FROM user_sessions WHERE session_token_hash = $1 AND expires_at > NOW() AND revoked_at IS NULL`
	UpdateSessionOrganization = `UPDATE user_sessions SET organization_id = NULLIF($1,'')::uuid, active_resource_id = NULLIF($1,'')::uuid, role_id = NULLIF($2,'')::uuid, last_activity_at = NOW() WHERE session_token_hash = $3 AND revoked_at IS NULL AND expires_at > NOW()`
	UpdateSessionContext      = `UPDATE user_sessions SET active_resource_id = NULLIF($1,'')::uuid, role_id = NULLIF($2,'')::uuid, last_activity_at = NOW() WHERE session_token_hash = $3 AND revoked_at IS NULL AND expires_at > NOW()`

	GetFirstTenantID = `SELECT id::text FROM tenants ORDER BY created_at ASC LIMIT 1`
	GetPermissionIDByCode = `SELECT id::text FROM permissions WHERE code = $1 LIMIT 1`
	InsertMembershipOnResource = `INSERT INTO memberships (tenant_id, user_id, resource_type, resource_id, status) VALUES ($1, $2, $3, $4, 'ACTIVE') RETURNING id`
	UserHasResourceMembership = `SELECT EXISTS(SELECT 1 FROM memberships WHERE user_id = $1 AND resource_id = $2 AND status = 'ACTIVE')`
	GetRoleIDForUserOnResource = `
		SELECT r.id::text FROM memberships m
		JOIN role_assignments ra ON ra.membership_id = m.id AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		JOIN roles r ON r.id = ra.role_id
		WHERE m.user_id = $1 AND m.resource_id = $2 AND m.status = 'ACTIVE'
		ORDER BY ra.created_at DESC NULLS LAST
		LIMIT 1`
	InsertIAMResource = `INSERT INTO iam_resources (tenant_id, resource_type, resource_id, parent_resource_id, name) VALUES ($1, $2, $3, NULLIF($4,'')::uuid, $5) RETURNING id`
	DeleteSession        = `DELETE FROM user_sessions WHERE session_token_hash = $1`

	InsertPasskeyChallenge = `INSERT INTO passkey_challenges (user_id, challenge, expires_at) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at`
	GetPasskeyChallenge    = `SELECT challenge FROM passkey_challenges WHERE user_id = $1 AND expires_at > NOW()`
	DeletePasskeyChallenge = `DELETE FROM passkey_challenges WHERE user_id = $1`
	InsertPasskey          = `INSERT INTO user_passkeys (user_id, credential_id, public_key, sign_count, device_name, backup_eligible, backed_up) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	GetPasskeysQuery       = `SELECT id, COALESCE(device_name, 'Passkey') AS device_name, created_at FROM user_passkeys WHERE user_id = $1 AND enabled = TRUE ORDER BY created_at DESC`
	GetPasskeyRecordsQuery = `SELECT credential_id, public_key, sign_count, COALESCE(device_name, '') AS device_name, backup_eligible, backed_up FROM user_passkeys WHERE user_id = $1 AND enabled = TRUE`
	UpdatePasskeySignCount = `UPDATE user_passkeys SET sign_count = $3, last_used_at = NOW(), updated_at = NOW() WHERE user_id = $1 AND credential_id = $2`
)

// Organization Queries
const (
	InsertOrganization = `INSERT INTO organizations (tenant_id, name, slug) VALUES ($1, $2, $3) RETURNING id`
	InsertOrgResource  = `INSERT INTO iam_resources (tenant_id, resource_type, resource_id, parent_resource_id) VALUES ($1, 'ORGANIZATION', $2, (SELECT id FROM iam_resources WHERE resource_id=$1 AND resource_type='TENANT'))`
	UpdateOrganization = `UPDATE organizations SET name = $1, updated_at = NOW() WHERE id = $2 RETURNING id`
	DeleteOrganization = `DELETE FROM organizations WHERE id = $1`
	InsertInvitation = `INSERT INTO invitations (tenant_id, email, resource_type, resource_id, role_id, status) VALUES ($1, $2, $3, $4, $5, 'PENDING') RETURNING id`
	GetPendingInvitation = `SELECT id FROM invitations WHERE email = $1 AND resource_id = $2 AND status = 'PENDING'`
	CheckExistingMembership = `SELECT id FROM memberships WHERE user_id = $1 AND resource_id = $2 AND status = 'ACTIVE'`
	UpdateInvitationStatus = `UPDATE invitations SET status = $1, updated_at = NOW() WHERE id = $2`
	GetInvitation = `SELECT id, tenant_id, email, resource_type, resource_id, role_id, status FROM invitations WHERE id = $1`
	GetIAMResourceID = `SELECT id FROM iam_resources WHERE resource_id = $1 AND resource_type = $2`
	InsertOrganizationMember = `INSERT INTO memberships (tenant_id, user_id, resource_type, resource_id, status) VALUES ((SELECT tenant_id FROM organizations WHERE id=$1), $2, 'ORGANIZATION', $1, 'ACTIVE') RETURNING id`
	GetOrgTenantID           = `SELECT tenant_id FROM organizations WHERE id = $1`
	DeleteOrganizationMember = `DELETE FROM memberships WHERE resource_type='ORGANIZATION' AND resource_id=$1 AND user_id=$2`
)

// Bootstrap Queries
const (
	CountTenants       = `SELECT count(id) FROM tenants`
	InsertTenant       = `INSERT INTO tenants (name, slug, tenant_type) VALUES ($1, $2, $3) RETURNING id`
	InsertTenantResource = `INSERT INTO iam_resources (tenant_id, resource_type, resource_id) VALUES ($1, 'TENANT', $1)`
	InsertSystemRole   = `INSERT INTO roles (tenant_id, name, description, is_system) VALUES ($1, $2, $3, $4) RETURNING id`
	UpdateRole         = `UPDATE roles SET name=$1, description=$2 WHERE id=$3`
	DeleteRole         = `DELETE FROM roles WHERE id=$1`
	InsertPermission   = `INSERT INTO permissions (resource_type, action, code, description) VALUES ($1, $2, $3, $4) ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code RETURNING id`
	InsertRolePerm     = `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`

	InsertProject      = `INSERT INTO projects (organization_id, name) VALUES ($1, $2) RETURNING id`
	GetProjects        = `SELECT id, name FROM projects WHERE organization_id=$1`
	UpdateProject      = `UPDATE projects SET name=$1 WHERE id=$2`
	DeleteProject      = `DELETE FROM projects WHERE id=$1`
	
	InsertOAuthProvider = `INSERT INTO tenant_oauth_providers (tenant_id, provider, client_id, client_secret) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, provider) DO UPDATE SET client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret, updated_at = NOW()`
)
