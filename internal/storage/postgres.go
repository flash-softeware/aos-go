package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/storage/queries"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	db *pgxpool.Pool
}

func NewPostgresStore(db *pgxpool.Pool) Repository {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return s.db.Begin(ctx)
}

func (s *PostgresStore) DB() *pgxpool.Pool {
	return s.db
}

// IAM
func (s *PostgresStore) CheckPermission(ctx context.Context, userID, resourceID, permission string) (bool, error) {
	var allowed bool
	err := s.db.QueryRow(ctx, queries.CheckPermission, userID, resourceID, permission).Scan(&allowed)
	return allowed, err
}

func (s *PostgresStore) InsertAuditLog(ctx context.Context, tenantID, userID, action, resourceType, resourceID, result string, details map[string]interface{}, ipAddress string) error {
	_, err := s.db.Exec(ctx, queries.InsertAuditLog, tenantID, userID, action, resourceType, resourceID, result, details, ipAddress)
	return err
}

func (s *PostgresStore) GetAuditLogs(ctx context.Context, tenantID, action string, limit, offset int) ([]response.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	var tenantArg any = tenantID
	if tenantID == "" {
		tenantArg = nil
	}
	rows, err := s.db.Query(ctx, queries.GetAuditLogs, tenantArg, action, limit, offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.AuditLog])
}

func (s *PostgresStore) ListUserSessions(ctx context.Context, userID string) ([]response.UserSession, error) {
	rows, err := s.db.Query(ctx, queries.ListUserSessions, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.UserSession])
}

func (s *PostgresStore) RevokeUserSession(ctx context.Context, userID, sessionID string) error {
	_, err := s.db.Exec(ctx, queries.RevokeUserSession, sessionID, userID)
	return err
}

func (s *PostgresStore) RevokeAllUserSessions(ctx context.Context, userID, exceptTokenHash string) error {
	_, err := s.db.Exec(ctx, queries.RevokeAllUserSessions, userID, exceptTokenHash)
	return err
}

func (s *PostgresStore) GetApiKeys(ctx context.Context, tenantID string) ([]response.ApiKey, error) {
	var tenantArg any = tenantID
	if tenantID == "" {
		tenantArg = nil
	}
	rows, err := s.db.Query(ctx, queries.GetApiKeys, tenantArg)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.ApiKey])
}

func (s *PostgresStore) CreateApiKey(ctx context.Context, tenantID, userID, name, keyPrefix, keyHash string, scopes []byte) (*response.ApiKey, string, error) {
	var tenantArg any = tenantID
	if tenantID == "" {
		tenantArg = nil
	}
	var key response.ApiKey
	err := s.db.QueryRow(ctx, queries.InsertApiKey, tenantArg, userID, name, keyPrefix, keyHash, scopes).Scan(
		&key.ID, &key.Name, &key.KeyPrefix, &key.Scopes, &key.CreatedAt,
	)
	return &key, keyPrefix, err
}

func (s *PostgresStore) RevokeApiKey(ctx context.Context, keyID string) error {
	_, err := s.db.Exec(ctx, queries.RevokeApiKey, keyID)
	return err
}

func (s *PostgresStore) GetWebhooks(ctx context.Context, tenantID string) ([]response.Webhook, error) {
	var tenantArg any = tenantID
	if tenantID == "" {
		tenantArg = nil
	}
	rows, err := s.db.Query(ctx, queries.GetWebhooks, tenantArg)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Webhook])
}

func (s *PostgresStore) CreateWebhook(ctx context.Context, tenantID, url, secret string, events []byte, createdBy string) (*response.Webhook, error) {
	var tenantArg any = tenantID
	if tenantID == "" {
		tenantArg = nil
	}
	var hook response.Webhook
	err := s.db.QueryRow(ctx, queries.InsertWebhook, tenantArg, url, secret, events, createdBy).Scan(
		&hook.ID, &hook.URL, &hook.Events, &hook.Enabled, &hook.CreatedAt,
	)
	return &hook, err
}

func (s *PostgresStore) DeleteWebhook(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, queries.DeleteWebhook, id)
	return err
}

func (s *PostgresStore) GetSecurityPolicies(ctx context.Context, tenantID, organizationID string) ([]response.SecurityPolicy, error) {
	var tenantArg, orgArg any = tenantID, organizationID
	if tenantID == "" {
		tenantArg = nil
	}
	if organizationID == "" {
		orgArg = nil
	}
	rows, err := s.db.Query(ctx, queries.GetSecurityPolicies, tenantArg, orgArg)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.SecurityPolicy])
}

func (s *PostgresStore) CreateSecurityPolicy(ctx context.Context, tenantID, organizationID, name, policyType string, configuration []byte) (*response.SecurityPolicy, error) {
	var tenantArg, orgArg any = tenantID, organizationID
	if tenantID == "" {
		tenantArg = nil
	}
	if organizationID == "" {
		orgArg = nil
	}
	var policy response.SecurityPolicy
	err := s.db.QueryRow(ctx, queries.InsertSecurityPolicy, tenantArg, orgArg, name, policyType, configuration).Scan(
		&policy.ID, &policy.Name, &policy.PolicyType, &policy.Configuration, &policy.Enabled, &policy.CreatedAt,
	)
	return &policy, err
}

func (s *PostgresStore) DeleteSecurityPolicy(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, queries.DeleteSecurityPolicy, id)
	return err
}

func (s *PostgresStore) GetTenantDomains(ctx context.Context, tenantID string) ([]response.TenantDomain, error) {
	rows, err := s.db.Query(ctx, queries.GetTenantDomains, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.TenantDomain])
}

func (s *PostgresStore) RegisterTenantDomain(ctx context.Context, tenantID, domain, verificationToken string) (*response.TenantDomain, error) {
	var d response.TenantDomain
	var token string
	err := s.db.QueryRow(ctx, queries.InsertTenantDomain, tenantID, domain, verificationToken).Scan(
		&d.ID, &d.TenantID, &d.Domain, &d.Verified, &token, &d.CreatedAt,
	)
	return &d, err
}

func (s *PostgresStore) VerifyTenantDomain(ctx context.Context, id string) (*response.TenantDomain, error) {
	var d response.TenantDomain
	err := s.db.QueryRow(ctx, queries.VerifyTenantDomain, id).Scan(&d.ID, &d.Domain, &d.Verified, &d.VerifiedAt)
	return &d, err
}

func (s *PostgresStore) DeleteTenantDomain(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, queries.DeleteTenantDomain, id)
	return err
}

func (s *PostgresStore) GetSsoConnections(ctx context.Context, orgID string) ([]response.SsoConnection, error) {
	rows, err := s.db.Query(ctx, queries.GetSsoConnections, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.SsoConnection])
}

func (s *PostgresStore) CreateSsoConnection(ctx context.Context, orgID, provider, name, issuerURL, clientID, createdBy string) (*response.SsoConnection, error) {
	var conn response.SsoConnection
	err := s.db.QueryRow(ctx, queries.InsertSsoConnection, orgID, provider, name, issuerURL, clientID, createdBy).Scan(
		&conn.ID, &conn.OrganizationID, &conn.Provider, &conn.Name, &conn.Enabled, &conn.IssuerURL, &conn.CreatedAt,
	)
	return &conn, err
}

func (s *PostgresStore) UpdateSsoConnectionEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := s.db.Exec(ctx, queries.UpdateSsoConnection, enabled, id)
	return err
}

func (s *PostgresStore) DeleteSsoConnection(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, queries.DeleteSsoConnection, id)
	return err
}

func (s *PostgresStore) GetScimConnections(ctx context.Context, orgID string) ([]response.ScimConnection, error) {
	rows, err := s.db.Query(ctx, queries.GetScimConnections, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.ScimConnection])
}

func (s *PostgresStore) CreateScimConnection(ctx context.Context, orgID, provider, tokenHash string) (*response.ScimConnection, error) {
	var conn response.ScimConnection
	err := s.db.QueryRow(ctx, queries.InsertScimConnection, orgID, provider, tokenHash).Scan(
		&conn.ID, &conn.OrganizationID, &conn.Provider, &conn.Enabled, &conn.CreatedAt,
	)
	return &conn, err
}

func (s *PostgresStore) RevokeScimConnection(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, queries.RevokeScimConnection, id)
	return err
}

func (s *PostgresStore) GetNetworkRules(ctx context.Context, orgID string) ([]response.NetworkRule, error) {
	rows, err := s.db.Query(ctx, queries.GetNetworkRules, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.NetworkRule])
}

func (s *PostgresStore) CreateNetworkRule(ctx context.Context, orgID, cidr, description string) (*response.NetworkRule, error) {
	var rule response.NetworkRule
	err := s.db.QueryRow(ctx, queries.InsertNetworkRule, orgID, cidr, description).Scan(
		&rule.ID, &rule.CIDR, &rule.Description, &rule.Enabled, &rule.CreatedAt,
	)
	return &rule, err
}

func (s *PostgresStore) DeleteNetworkRule(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, queries.DeleteNetworkRule, id)
	return err
}

func (s *PostgresStore) GetMfaStatus(ctx context.Context, userID string) (bool, bool, error) {
	var enabled, verified bool
	err := s.db.QueryRow(ctx, queries.GetMfaStatusRow, userID).Scan(&enabled, &verified)
	if err == pgx.ErrNoRows {
		return false, false, nil
	}
	return enabled, verified, err
}

func (s *PostgresStore) UpsertMfaSecret(ctx context.Context, userID, secret string) error {
	_, err := s.db.Exec(ctx, queries.UpsertMfaSecret, userID, secret)
	return err
}

func (s *PostgresStore) GetMfaSecret(ctx context.Context, userID string) (string, error) {
	var secret *string
	err := s.db.QueryRow(ctx, queries.GetMfaSecret, userID).Scan(&secret)
	if err == pgx.ErrNoRows || secret == nil {
		return "", nil
	}
	return *secret, err
}

func (s *PostgresStore) EnableMfa(ctx context.Context, userID string, recoveryCodes []string) error {
	raw, _ := json.Marshal(recoveryCodes)
	_, err := s.db.Exec(ctx, queries.EnableMfa, userID, raw)
	return err
}

func (s *PostgresStore) GetMfaWithRecovery(ctx context.Context, userID string) (string, []string, error) {
	var secret *string
	var raw []byte
	err := s.db.QueryRow(ctx, queries.GetMfaWithRecovery, userID).Scan(&secret, &raw)
	if err == pgx.ErrNoRows || secret == nil {
		return "", nil, err
	}
	var codes []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &codes)
	}
	return *secret, codes, nil
}

func (s *PostgresStore) UpdateMfaRecoveryCodes(ctx context.Context, userID string, recoveryCodes []string) error {
	raw, _ := json.Marshal(recoveryCodes)
	_, err := s.db.Exec(ctx, queries.UpdateMfaRecoveryCodes, userID, raw)
	return err
}

func (s *PostgresStore) DisableMfa(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, queries.DisableMfa, userID)
	return err
}

func (s *PostgresStore) InsertMfaChallenge(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.Exec(ctx, queries.InsertMfaChallenge, userID, tokenHash, expiresAt)
	return err
}

func (s *PostgresStore) ConsumeMfaChallenge(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	err := s.db.QueryRow(ctx, queries.ConsumeMfaChallenge, tokenHash).Scan(&userID)
	return userID, err
}

// Auth
func (s *PostgresStore) GetUserAuth(ctx context.Context, email string) (string, string, error) {
	var userID, hash string
	err := s.db.QueryRow(ctx, queries.GetUserAuth, email).Scan(&userID, &hash)
	return userID, hash, err
}

func (s *PostgresStore) GetUserIDByEmail(ctx context.Context, email string) (string, error) {
	var userID string
	err := s.db.QueryRow(ctx, queries.GetUserIDByEmail, email).Scan(&userID)
	return userID, err
}

func (s *PostgresStore) GetUserDefaultTenant(ctx context.Context, userID string) (string, error) {
	var tenantID string
	err := s.db.QueryRow(ctx, queries.GetUserDefaultTenant, userID).Scan(&tenantID)
	// it is ok if no tenant is found, we can return empty string
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return tenantID, err
}

func (s *PostgresStore) InsertSession(ctx context.Context, tx pgx.Tx, userID, tenantID, orgID, roleID, sessionTokenHash string, expiresAt interface{}) error {
	_, err := tx.Exec(ctx, queries.InsertSession, userID, tenantID, orgID, roleID, sessionTokenHash, expiresAt)
	return err
}

func (s *PostgresStore) ValidateSessionToken(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	err := s.db.QueryRow(ctx, queries.ValidateSessionToken, tokenHash).Scan(&userID)
	return userID, err
}

func (s *PostgresStore) GetSessionByToken(ctx context.Context, tokenHash string) (string, string, string, string, error) {
	var userID, tenantID, orgID, roleID string
	err := s.db.QueryRow(ctx, queries.GetSessionByToken, tokenHash).Scan(&userID, &tenantID, &orgID, &roleID)
	return userID, tenantID, orgID, roleID, err
}

func (s *PostgresStore) UpdateSessionOrganization(ctx context.Context, tokenHash, orgID, roleID string) error {
	_, err := s.db.Exec(ctx, queries.UpdateSessionOrganization, orgID, roleID, tokenHash)
	return err
}

func (s *PostgresStore) GetUserByID(ctx context.Context, userID string) (*response.User, error) {
	var user response.User
	var status string
	err := s.db.QueryRow(ctx, queries.GetUserByID, userID).Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName, &status)
	if err != nil {
		return nil, err
	}
	user.Status = status
	return &user, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.Exec(ctx, queries.DeleteSession, tokenHash)
	return err
}

func (s *PostgresStore) InsertPasskeyChallenge(ctx context.Context, userID, challenge string, expiresAt time.Time) error {
	_, err := s.db.Exec(ctx, queries.InsertPasskeyChallenge, userID, challenge, expiresAt)
	return err
}

func (s *PostgresStore) GetPasskeyChallenge(ctx context.Context, userID string) (string, error) {
	var challenge string
	err := s.db.QueryRow(ctx, queries.GetPasskeyChallenge, userID).Scan(&challenge)
	return challenge, err
}

func (s *PostgresStore) DeletePasskeyChallenge(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, queries.DeletePasskeyChallenge, userID)
	return err
}

func (s *PostgresStore) InsertPasskey(ctx context.Context, userID, credentialID, publicKey string, signCount int64, deviceName string, backupEligible, backedUp bool) error {
	_, err := s.db.Exec(ctx, queries.InsertPasskey, userID, credentialID, publicKey, signCount, deviceName, backupEligible, backedUp)
	return err
}

func (s *PostgresStore) GetPasskeys(ctx context.Context, userID string) ([]response.Passkey, error) {
	rows, err := s.db.Query(ctx, queries.GetPasskeysQuery, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Passkey])
}

func (s *PostgresStore) GetPasskeyRecords(ctx context.Context, userID string) ([]response.PasskeyRecord, error) {
	rows, err := s.db.Query(ctx, queries.GetPasskeyRecordsQuery, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.PasskeyRecord])
}

func (s *PostgresStore) UpdatePasskeySignCount(ctx context.Context, userID, credentialID string, signCount int64) error {
	_, err := s.db.Exec(ctx, queries.UpdatePasskeySignCount, userID, credentialID, signCount)
	return err
}

// Organization
func (s *PostgresStore) InsertOrganization(ctx context.Context, tx pgx.Tx, tenantID, name, slug string) (string, error) {
	var orgID string
	err := tx.QueryRow(ctx, queries.InsertOrganization, tenantID, name, slug).Scan(&orgID)
	return orgID, err
}

func (s *PostgresStore) UpdateOrganization(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	_, err := tx.Exec(ctx, queries.UpdateOrganization, name, orgID)
	return err
}

func (s *PostgresStore) DeleteOrganization(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx, queries.DeleteOrganization, orgID)
	return err
}

func (s *PostgresStore) InsertInvitation(ctx context.Context, tx pgx.Tx, tenantID, email, resourceType, resourceID, roleID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, queries.InsertInvitation, tenantID, email, resourceType, resourceID, roleID).Scan(&id)
	return id, err
}

func (s *PostgresStore) CheckPendingInvitation(ctx context.Context, email, resourceID string) (bool, error) {
	var id string
	err := s.db.QueryRow(ctx, queries.GetPendingInvitation, email, resourceID).Scan(&id)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *PostgresStore) CheckExistingMembership(ctx context.Context, userID, resourceID string) (bool, error) {
	var id string
	err := s.db.QueryRow(ctx, queries.CheckExistingMembership, userID, resourceID).Scan(&id)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *PostgresStore) InsertOrgResource(ctx context.Context, tx pgx.Tx, tenantID, orgID string) error {
	_, err := tx.Exec(ctx, queries.InsertOrgResource, tenantID, orgID)
	return err
}

func (s *PostgresStore) InsertOrganizationMember(ctx context.Context, tx pgx.Tx, orgID, userID, roleID string) error {
	var membershipID string
	err := tx.QueryRow(ctx, queries.InsertOrganizationMember, orgID, userID).Scan(&membershipID)
	if err != nil {
		return err
	}
	
	iamResourceID, err := s.GetIAMResource(ctx, tx, orgID, "ORGANIZATION")
	if err != nil {
		return err
	}
	return s.InsertRoleAssignment(ctx, tx, membershipID, iamResourceID, roleID)
}

func (s *PostgresStore) DeleteOrganizationMember(ctx context.Context, tx pgx.Tx, orgID, userID string) error {
	_, err := tx.Exec(ctx, queries.DeleteOrganizationMember, orgID, userID)
	return err
}

// User
func (s *PostgresStore) InsertUser(ctx context.Context, tx pgx.Tx, email, firstName, lastName string) (string, error) {
	var userID string
	err := tx.QueryRow(ctx, queries.InsertUser, email, firstName, lastName).Scan(&userID)
	return userID, err
}

func (s *PostgresStore) InsertAuthAccount(ctx context.Context, tx pgx.Tx, userID, passwordHash string) error {
	_, err := tx.Exec(ctx, queries.InsertAuthAccount, userID, passwordHash)
	return err
}

func (s *PostgresStore) GetRoleByName(ctx context.Context, tx pgx.Tx, tenantID, roleName string) (string, error) {
	var roleID string
	err := tx.QueryRow(ctx, queries.GetRoleByName, tenantID, roleName).Scan(&roleID)
	return roleID, err
}

func (s *PostgresStore) GetRoleByNameCtx(ctx context.Context, tenantID, roleName string) (string, error) {
	var roleID string
	err := s.db.QueryRow(ctx, queries.GetRoleByName, tenantID, roleName).Scan(&roleID)
	return roleID, err
}

func (s *PostgresStore) InsertMembership(ctx context.Context, tx pgx.Tx, tenantID, userID string) (string, error) {
	var membershipID string
	err := tx.QueryRow(ctx, queries.InsertMembership, tenantID, userID).Scan(&membershipID)
	return membershipID, err
}

func (s *PostgresStore) InsertMembershipOnResource(ctx context.Context, tx pgx.Tx, tenantID, userID, resourceType, resourceID string) (string, error) {
	var membershipID string
	err := tx.QueryRow(ctx, queries.InsertMembershipOnResource, tenantID, userID, resourceType, resourceID).Scan(&membershipID)
	return membershipID, err
}

func (s *PostgresStore) InsertIAMResource(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID, parentIAMID, name string) (string, error) {
	var iamID string
	err := tx.QueryRow(ctx, queries.InsertIAMResource, tenantID, resourceType, resourceID, parentIAMID, name).Scan(&iamID)
	return iamID, err
}

func (s *PostgresStore) GetFirstTenantID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRow(ctx, queries.GetFirstTenantID).Scan(&id)
	return id, err
}

func (s *PostgresStore) GetPermissionIDByCode(ctx context.Context, code string) (string, error) {
	var id string
	err := s.db.QueryRow(ctx, queries.GetPermissionIDByCode, code).Scan(&id)
	return id, err
}

func (s *PostgresStore) UserHasResourceMembership(ctx context.Context, userID, resourceID string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, queries.UserHasResourceMembership, userID, resourceID).Scan(&ok)
	return ok, err
}

func (s *PostgresStore) GetRoleIDForUserOnResource(ctx context.Context, userID, resourceID string) (string, error) {
	var roleID string
	err := s.db.QueryRow(ctx, queries.GetRoleIDForUserOnResource, userID, resourceID).Scan(&roleID)
	return roleID, err
}

func (s *PostgresStore) UpdateSessionContext(ctx context.Context, tokenHash, activeResourceID, roleID string) error {
	_, err := s.db.Exec(ctx, queries.UpdateSessionContext, activeResourceID, roleID, tokenHash)
	return err
}

func (s *PostgresStore) GetIAMResource(ctx context.Context, tx pgx.Tx, resourceID, resourceType string) (string, error) {
	var iamResID string
	err := tx.QueryRow(ctx, queries.GetIAMResource, resourceID, resourceType).Scan(&iamResID)
	return iamResID, err
}

func (s *PostgresStore) InsertRoleAssignment(ctx context.Context, tx pgx.Tx, membershipID, resourceID, roleID string) error {
	_, err := tx.Exec(ctx, queries.InsertRoleAssignment, membershipID, resourceID, roleID)
	return err
}

// Management
func (s *PostgresStore) GetUsers(ctx context.Context) ([]response.User, error) {
	rows, _ := s.db.Query(ctx, queries.GetUsers)
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.User])
}
func (s *PostgresStore) GetRoles(ctx context.Context) ([]response.Role, error) {
	rows, _ := s.db.Query(ctx, queries.GetRoles)
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Role])
}
func (s *PostgresStore) GetOrganizations(ctx context.Context) ([]response.Organization, error) {
	rows, _ := s.db.Query(ctx, queries.GetOrganizations)
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Organization])
}
func (s *PostgresStore) GetPermissions(ctx context.Context) ([]response.Permission, error) {
	rows, _ := s.db.Query(ctx, queries.GetPermissions)
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Permission])
}

func (s *PostgresStore) GetRolePermissionIDs(ctx context.Context, roleID string) ([]string, error) {
	rows, err := s.db.Query(ctx, queries.GetRolePermissions, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *PostgresStore) DeleteRolePermissions(ctx context.Context, tx pgx.Tx, roleID string) error {
	_, err := tx.Exec(ctx, queries.DeleteRolePerms, roleID)
	return err
}
func (s *PostgresStore) GetMemberships(ctx context.Context) ([]response.Membership, error) {
	rows, _ := s.db.Query(ctx, queries.GetMemberships)
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Membership])
}

func (s *PostgresStore) GetUserOrganizations(ctx context.Context, userID string) ([]response.UserOrganization, error) {
	rows, err := s.db.Query(ctx, queries.GetUserOrganizations, userID)
	if err != nil {
		return nil, err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowToStructByName[response.UserOrganization])
	if err != nil {
		return nil, err
	}
	if orgs == nil {
		return []response.UserOrganization{}, nil
	}
	return orgs, nil
}

func (s *PostgresStore) UserHasOrgMembership(ctx context.Context, userID, orgID string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, queries.UserHasOrgMembership, userID, orgID).Scan(&ok)
	return ok, err
}

func (s *PostgresStore) GetOrgMembers(ctx context.Context, orgID string) ([]response.OrgMember, error) {
	rows, err := s.db.Query(ctx, queries.GetOrgMembers, orgID)
	if err != nil {
		return nil, err
	}
	members, err := pgx.CollectRows(rows, pgx.RowToStructByName[response.OrgMember])
	if err != nil {
		return nil, err
	}
	if members == nil {
		return []response.OrgMember{}, nil
	}
	return members, nil
}

func (s *PostgresStore) GetUserPermissionCodes(ctx context.Context, userID, resourceID string) ([]string, error) {
	rows, err := s.db.Query(ctx, queries.GetUserPermissionCodes, userID, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	if codes == nil {
		return []string{}, nil
	}
	return codes, rows.Err()
}

func (s *PostgresStore) GetTenants(ctx context.Context) ([]response.Tenant, error) {
	rows, _ := s.db.Query(ctx, queries.GetTenants)
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Tenant])
}
func (s *PostgresStore) GetOAuthProviders(ctx context.Context, tenantID string) ([]response.OAuthProvider, error) {
	rows, err := s.db.Query(ctx, queries.GetOAuthProviders, tenantID)
	if err != nil {
		return nil, err
	}
	providers, err := pgx.CollectRows(rows, pgx.RowToStructByName[response.OAuthProvider])
	if err != nil {
		return nil, err
	}
	if providers == nil {
		return []response.OAuthProvider{}, nil
	}
	return providers, nil
}

func (s *PostgresStore) UpdateRole(ctx context.Context, tx pgx.Tx, id, name, desc string) error {
	_, err := tx.Exec(ctx, queries.UpdateRole, name, desc, id)
	return err
}
func (s *PostgresStore) DeleteRole(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, queries.DeleteRole, id)
	return err
}
func (s *PostgresStore) InsertProject(ctx context.Context, tx pgx.Tx, orgID, name string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, queries.InsertProject, orgID, name).Scan(&id)
	return id, err
}
func (s *PostgresStore) GetProjects(ctx context.Context, orgID string) ([]response.Project, error) {
	rows, _ := s.db.Query(ctx, queries.GetProjects, orgID)
	return pgx.CollectRows(rows, pgx.RowToStructByName[response.Project])
}
func (s *PostgresStore) UpdateProject(ctx context.Context, tx pgx.Tx, id, name string) error {
	_, err := tx.Exec(ctx, queries.UpdateProject, name, id)
	return err
}
func (s *PostgresStore) DeleteProject(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, queries.DeleteProject, id)
	return err
}
func (s *PostgresStore) InsertOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID, provider, clientID, clientSecret string) error {
	_, err := tx.Exec(ctx, queries.InsertOAuthProvider, tenantID, provider, clientID, clientSecret)
	return err
}

// Bootstrap
func (s *PostgresStore) CountTenants(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, queries.CountTenants).Scan(&count)
	return count, err
}

func (s *PostgresStore) InsertTenant(ctx context.Context, tx pgx.Tx, name, slug, tenantType string) (string, error) {
	var tenantID string
	err := tx.QueryRow(ctx, queries.InsertTenant, name, slug, tenantType).Scan(&tenantID)
	return tenantID, err
}

func (s *PostgresStore) InsertTenantResource(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, queries.InsertTenantResource, tenantID)
	return err
}

func (s *PostgresStore) InsertSystemRole(ctx context.Context, tx pgx.Tx, tenantID, name, description string, isSystem bool) (string, error) {
	var roleID string
	err := tx.QueryRow(ctx, queries.InsertSystemRole, tenantID, name, description, isSystem).Scan(&roleID)
	return roleID, err
}

func (s *PostgresStore) InsertPermission(ctx context.Context, tx pgx.Tx, resourceType, action, code, description string) (string, error) {
	var permID string
	err := tx.QueryRow(ctx, queries.InsertPermission, resourceType, action, code, description).Scan(&permID)
	return permID, err
}

func (s *PostgresStore) InsertRolePerm(ctx context.Context, tx pgx.Tx, roleID, permissionID string) error {
	_, err := tx.Exec(ctx, queries.InsertRolePerm, roleID, permissionID)
	return err
}

func hashStorageToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *PostgresStore) InsertUserWithStatus(ctx context.Context, tx pgx.Tx, email, firstName, lastName, status string) (string, error) {
	var userID string
	err := tx.QueryRow(ctx, queries.InsertUserWithStatus, email, firstName, lastName, status).Scan(&userID)
	return userID, err
}

func (s *PostgresStore) InsertUserToken(ctx context.Context, userID, tokenType, plainToken string, metadata []byte, expiresAt time.Time) error {
	if metadata == nil {
		metadata = []byte("{}")
	}
	_, err := s.db.Exec(ctx, queries.InsertUserToken, userID, tokenType, hashStorageToken(plainToken), metadata, expiresAt)
	return err
}

func (s *PostgresStore) InsertUserTokenTx(ctx context.Context, tx pgx.Tx, userID, tokenType, plainToken string, metadata []byte, expiresAt time.Time) error {
	if metadata == nil {
		metadata = []byte("{}")
	}
	_, err := tx.Exec(ctx, queries.InsertUserToken, userID, tokenType, hashStorageToken(plainToken), metadata, expiresAt)
	return err
}

func (s *PostgresStore) ConsumeUserToken(ctx context.Context, tokenHash, tokenType string) (string, error) {
	var userID string
	err := s.db.QueryRow(ctx, queries.ConsumeUserToken, tokenHash, tokenType).Scan(&userID)
	if err == pgx.ErrNoRows {
		return "", errors.New("invalid token")
	}
	return userID, err
}

func (s *PostgresStore) ConsumeUserTokenWithMetadata(ctx context.Context, tokenHash, tokenType string) (string, []byte, error) {
	var userID string
	var metadata []byte
	err := s.db.QueryRow(ctx, queries.ConsumeUserTokenWithMeta, tokenHash, tokenType).Scan(&userID, &metadata)
	if err == pgx.ErrNoRows {
		return "", nil, errors.New("invalid token")
	}
	return userID, metadata, err
}

func (s *PostgresStore) UpdateLocalPassword(ctx context.Context, userID, passwordHash string) error {
	tag, err := s.db.Exec(ctx, queries.UpdateLocalPassword, passwordHash, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		_, err = s.db.Exec(ctx, queries.InsertLocalAuthAccount, userID, passwordHash)
	}
	return err
}

func (s *PostgresStore) ActivateUserEmail(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, queries.ActivateUserEmail, userID)
	return err
}

func (s *PostgresStore) CompleteInvitationAcceptance(ctx context.Context, userID, firstName, lastName, passwordHash string) error {
	tx, err := s.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, queries.CompleteInvitationUser, firstName, lastName, userID); err != nil {
		return err
	}

	tag, err := tx.Exec(ctx, queries.UpdateLocalPassword, passwordHash, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := tx.Exec(ctx, queries.InsertLocalAuthAccount, userID, passwordHash); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, queries.ActivatePendingMemberships, userID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) InsertPendingOrganizationMember(ctx context.Context, tx pgx.Tx, tenantID, orgID, userID, roleID string) error {
	var membershipID string
	if err := tx.QueryRow(ctx, queries.InsertPendingOrgMember, tenantID, userID, orgID).Scan(&membershipID); err != nil {
		return err
	}
	iamResourceID, err := s.GetIAMResource(ctx, tx, orgID, "ORGANIZATION")
	if err != nil {
		return err
	}
	return s.InsertRoleAssignment(ctx, tx, membershipID, iamResourceID, roleID)
}

func (s *PostgresStore) GetOAuthProviderCredentials(ctx context.Context, tenantID, provider string) (string, string, error) {
	var clientID, clientSecret string
	err := s.db.QueryRow(ctx, queries.GetOAuthProviderCreds, tenantID, provider).Scan(&clientID, &clientSecret)
	if err == pgx.ErrNoRows {
		return "", "", nil
	}
	return clientID, clientSecret, err
}

func (s *PostgresStore) FindOrCreateOAuthUser(ctx context.Context, tenantID, provider, providerUserID, email, firstName, lastName string) (string, error) {
	var existingUserID string
	err := s.db.QueryRow(ctx, queries.GetAuthAccountByProvider, provider, providerUserID).Scan(&existingUserID)
	if err == nil && existingUserID != "" {
		return existingUserID, nil
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	userID, err := s.GetUserIDByEmail(ctx, email)
	if err != nil || userID == "" {
		if firstName == "" {
			firstName = "OAuth"
		}
		if lastName == "" {
			lastName = "User"
		}
		userID, err = s.InsertUserWithStatus(ctx, tx, email, firstName, lastName, "ACTIVE")
		if err != nil {
			return "", err
		}

		membershipID, err := s.InsertMembership(ctx, tx, tenantID, userID)
		if err != nil {
			return "", err
		}
		memberRoleID, _ := s.GetRoleByName(ctx, tx, tenantID, "Member")
		if memberRoleID != "" {
			iamResID, err := s.GetIAMResource(ctx, tx, tenantID, "TENANT")
			if err == nil {
				_ = s.InsertRoleAssignment(ctx, tx, membershipID, iamResID, memberRoleID)
			}
		}
	}

	if _, err := tx.Exec(ctx, queries.InsertOAuthAccount, userID, provider, providerUserID); err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *PostgresStore) GetOrgTenantID(ctx context.Context, orgID string) (string, error) {
	var tenantID string
	err := s.db.QueryRow(ctx, queries.GetOrgTenantID, orgID).Scan(&tenantID)
	return tenantID, err
}

