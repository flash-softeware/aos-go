package storage

import (
	"context"
	"time"

	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository defines all operations available in the SDK storage layer
type Repository interface {
	BeginTx(ctx context.Context) (pgx.Tx, error)
	DB() *pgxpool.Pool

	// IAM
	CheckPermission(ctx context.Context, userID, resourceID, permission string) (bool, error)
	InsertAuditLog(ctx context.Context, tenantID, userID, action, resourceType, resourceID, result string, details map[string]interface{}, ipAddress string) error
	GetAuditLogs(ctx context.Context, tenantID, action string, limit, offset int) ([]response.AuditLog, error)

	ListUserSessions(ctx context.Context, userID string) ([]response.UserSession, error)
	RevokeUserSession(ctx context.Context, userID, sessionID string) error
	RevokeAllUserSessions(ctx context.Context, userID, exceptTokenHash string) error

	GetApiKeys(ctx context.Context, tenantID string) ([]response.ApiKey, error)
	CreateApiKey(ctx context.Context, tenantID, userID, name, keyPrefix, keyHash string, scopes []byte) (*response.ApiKey, string, error)
	RevokeApiKey(ctx context.Context, keyID string) error

	GetWebhooks(ctx context.Context, tenantID string) ([]response.Webhook, error)
	CreateWebhook(ctx context.Context, tenantID, url, secret string, events []byte, createdBy string) (*response.Webhook, error)
	DeleteWebhook(ctx context.Context, id string) error

	GetSecurityPolicies(ctx context.Context, tenantID, organizationID string) ([]response.SecurityPolicy, error)
	CreateSecurityPolicy(ctx context.Context, tenantID, organizationID, name, policyType string, configuration []byte) (*response.SecurityPolicy, error)
	DeleteSecurityPolicy(ctx context.Context, id string) error

	GetTenantDomains(ctx context.Context, tenantID string) ([]response.TenantDomain, error)
	RegisterTenantDomain(ctx context.Context, tenantID, domain, verificationToken string) (*response.TenantDomain, error)
	VerifyTenantDomain(ctx context.Context, id string) (*response.TenantDomain, error)
	DeleteTenantDomain(ctx context.Context, id string) error

	GetSsoConnections(ctx context.Context, orgID string) ([]response.SsoConnection, error)
	CreateSsoConnection(ctx context.Context, orgID, provider, name, issuerURL, clientID, createdBy string) (*response.SsoConnection, error)
	UpdateSsoConnectionEnabled(ctx context.Context, id string, enabled bool) error
	DeleteSsoConnection(ctx context.Context, id string) error

	GetScimConnections(ctx context.Context, orgID string) ([]response.ScimConnection, error)
	CreateScimConnection(ctx context.Context, orgID, provider, tokenHash string) (*response.ScimConnection, error)
	RevokeScimConnection(ctx context.Context, id string) error

	GetNetworkRules(ctx context.Context, orgID string) ([]response.NetworkRule, error)
	CreateNetworkRule(ctx context.Context, orgID, cidr, description string) (*response.NetworkRule, error)
	DeleteNetworkRule(ctx context.Context, id string) error

	GetMfaStatus(ctx context.Context, userID string) (enabled, verified bool, err error)
	UpsertMfaSecret(ctx context.Context, userID, secret string) error
	GetMfaSecret(ctx context.Context, userID string) (string, error)
	EnableMfa(ctx context.Context, userID string, recoveryCodes []string) error
	GetMfaWithRecovery(ctx context.Context, userID string) (secret string, recoveryCodes []string, err error)
	UpdateMfaRecoveryCodes(ctx context.Context, userID string, recoveryCodes []string) error
	DisableMfa(ctx context.Context, userID string) error
	InsertMfaChallenge(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	ConsumeMfaChallenge(ctx context.Context, tokenHash string) (string, error)

	// Auth
	GetUserAuth(ctx context.Context, email string) (string, string, error)
	GetUserIDByEmail(ctx context.Context, email string) (string, error)
	GetUserDefaultTenant(ctx context.Context, userID string) (string, error)
	InsertUserToken(ctx context.Context, userID, tokenType, plainToken string, metadata []byte, expiresAt time.Time) error
	InsertUserTokenTx(ctx context.Context, tx pgx.Tx, userID, tokenType, plainToken string, metadata []byte, expiresAt time.Time) error
	ConsumeUserToken(ctx context.Context, tokenHash, tokenType string) (string, error)
	ConsumeUserTokenWithMetadata(ctx context.Context, tokenHash, tokenType string) (string, []byte, error)
	UpdateLocalPassword(ctx context.Context, userID, passwordHash string) error
	ActivateUserEmail(ctx context.Context, userID string) error
	CompleteInvitationAcceptance(ctx context.Context, userID, firstName, lastName, passwordHash string) error
	InsertPendingOrganizationMember(ctx context.Context, tx pgx.Tx, tenantID, orgID, userID, roleID string) error
	GetOAuthProviderCredentials(ctx context.Context, tenantID, provider string) (clientID, clientSecret string, err error)
	FindOrCreateOAuthUser(ctx context.Context, tenantID, provider, providerUserID, email, firstName, lastName string) (string, error)
	GetOrgTenantID(ctx context.Context, orgID string) (string, error)
	InsertSession(ctx context.Context, tx pgx.Tx, userID, tenantID, orgID, roleID, sessionTokenHash string, expiresAt interface{}) error
	ValidateSessionToken(ctx context.Context, tokenHash string) (string, error)
	GetSessionByToken(ctx context.Context, tokenHash string) (userID, tenantID, orgID, roleID string, err error)
	UpdateSessionOrganization(ctx context.Context, tokenHash, orgID, roleID string) error
	DeleteSession(ctx context.Context, tokenHash string) error
	GetUserByID(ctx context.Context, userID string) (*response.User, error)
	
	InsertPasskeyChallenge(ctx context.Context, userID, challenge string, expiresAt time.Time) error
	GetPasskeyChallenge(ctx context.Context, userID string) (string, error)
	DeletePasskeyChallenge(ctx context.Context, userID string) error
	InsertPasskey(ctx context.Context, userID, credentialID, publicKey string, signCount int64, deviceName string, backupEligible, backedUp bool) error
	GetPasskeys(ctx context.Context, userID string) ([]response.Passkey, error)
	GetPasskeyRecords(ctx context.Context, userID string) ([]response.PasskeyRecord, error)
	UpdatePasskeySignCount(ctx context.Context, userID, credentialID string, signCount int64) error

	// Organization
	InsertOrganization(ctx context.Context, tx pgx.Tx, tenantID, name, slug string) (string, error)
	InsertOrgResource(ctx context.Context, tx pgx.Tx, tenantID, orgID string) error
	UpdateOrganization(ctx context.Context, tx pgx.Tx, orgID, name string) error
	DeleteOrganization(ctx context.Context, tx pgx.Tx, orgID string) error
	
	InsertInvitation(ctx context.Context, tx pgx.Tx, tenantID, email, resourceType, resourceID, roleID string) (string, error)
	CheckPendingInvitation(ctx context.Context, email, resourceID string) (bool, error)
	CheckExistingMembership(ctx context.Context, userID, resourceID string) (bool, error)
	
	InsertOrganizationMember(ctx context.Context, tx pgx.Tx, orgID, userID, roleID string) error
	DeleteOrganizationMember(ctx context.Context, tx pgx.Tx, orgID, userID string) error

	// User
	InsertUser(ctx context.Context, tx pgx.Tx, email, firstName, lastName string) (string, error)
	InsertUserWithStatus(ctx context.Context, tx pgx.Tx, email, firstName, lastName, status string) (string, error)
	InsertAuthAccount(ctx context.Context, tx pgx.Tx, userID, passwordHash string) error
	GetRoleByName(ctx context.Context, tx pgx.Tx, tenantID, roleName string) (string, error)
	GetRoleByNameCtx(ctx context.Context, tenantID, roleName string) (string, error)
	InsertMembership(ctx context.Context, tx pgx.Tx, tenantID, userID string) (string, error)
	InsertMembershipOnResource(ctx context.Context, tx pgx.Tx, tenantID, userID, resourceType, resourceID string) (string, error)
	GetIAMResource(ctx context.Context, tx pgx.Tx, resourceID, resourceType string) (string, error)
	InsertIAMResource(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID, parentIAMID, name string) (string, error)
	InsertRoleAssignment(ctx context.Context, tx pgx.Tx, membershipID, resourceID, roleID string) error
	GetFirstTenantID(ctx context.Context) (string, error)
	GetPermissionIDByCode(ctx context.Context, code string) (string, error)
	UserHasResourceMembership(ctx context.Context, userID, resourceID string) (bool, error)
	GetRoleIDForUserOnResource(ctx context.Context, userID, resourceID string) (string, error)
	UpdateSessionContext(ctx context.Context, tokenHash, activeResourceID, roleID string) error

	// Management & Bootstrap
	GetUsers(ctx context.Context) ([]response.User, error)
	GetRoles(ctx context.Context) ([]response.Role, error)
	GetOrganizations(ctx context.Context) ([]response.Organization, error)
	GetPermissions(ctx context.Context) ([]response.Permission, error)
	GetRolePermissionIDs(ctx context.Context, roleID string) ([]string, error)
	DeleteRolePermissions(ctx context.Context, tx pgx.Tx, roleID string) error
	GetMemberships(ctx context.Context) ([]response.Membership, error)
	GetUserOrganizations(ctx context.Context, userID string) ([]response.UserOrganization, error)
	UserHasOrgMembership(ctx context.Context, userID, orgID string) (bool, error)
	GetOrgMembers(ctx context.Context, orgID string) ([]response.OrgMember, error)
	GetUserPermissionCodes(ctx context.Context, userID, resourceID string) ([]string, error)
	GetTenants(ctx context.Context) ([]response.Tenant, error)
	GetOAuthProviders(ctx context.Context, tenantID string) ([]response.OAuthProvider, error)

	UpdateRole(ctx context.Context, tx pgx.Tx, id, name, desc string) error
	DeleteRole(ctx context.Context, tx pgx.Tx, id string) error

	InsertProject(ctx context.Context, tx pgx.Tx, orgID, name string) (string, error)
	GetProjects(ctx context.Context, orgID string) ([]response.Project, error)
	UpdateProject(ctx context.Context, tx pgx.Tx, id, name string) error
	DeleteProject(ctx context.Context, tx pgx.Tx, id string) error

	InsertOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID, provider, clientID, clientSecret string) error

	CountTenants(ctx context.Context) (int, error)
	InsertTenant(ctx context.Context, tx pgx.Tx, name, slug, tenantType string) (string, error)
	InsertTenantResource(ctx context.Context, tx pgx.Tx, tenantID string) error
	InsertSystemRole(ctx context.Context, tx pgx.Tx, tenantID, name, description string, isSystem bool) (string, error)
	InsertPermission(ctx context.Context, tx pgx.Tx, resourceType, action, code, description string) (string, error)
	InsertRolePerm(ctx context.Context, tx pgx.Tx, roleID, permissionID string) error
}
