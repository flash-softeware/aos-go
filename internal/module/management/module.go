package management

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/storage"
)

type Module struct {
	store storage.Repository
}

func New(store storage.Repository) *Module {
	return &Module{store: store}
}

func (m *Module) CreateRole(ctx context.Context, tenantID, name, description string) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	roleID, err := m.store.InsertSystemRole(ctx, tx, tenantID, name, description, false)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	return roleID, nil
}

func (m *Module) CreatePermission(ctx context.Context, resourceType, action, code, description string) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	permID, err := m.store.InsertPermission(ctx, tx, resourceType, action, code, description)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	return permID, nil
}

func (m *Module) GetRolePermissionIDs(ctx context.Context, roleID string) ([]string, error) {
	return m.store.GetRolePermissionIDs(ctx, roleID)
}

func (m *Module) ReplaceRolePermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.DeleteRolePermissions(ctx, tx, roleID); err != nil {
		return err
	}

	for _, permID := range permissionIDs {
		if err := m.store.InsertRolePerm(ctx, tx, roleID, permID); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (m *Module) AssignUserRole(ctx context.Context, membershipID, resourceID, roleID string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.InsertRoleAssignment(ctx, tx, membershipID, resourceID, roleID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (m *Module) GetUsers(ctx context.Context) ([]response.User, error) { return m.store.GetUsers(ctx) }
func (m *Module) GetRoles(ctx context.Context) ([]response.Role, error) { return m.store.GetRoles(ctx) }
func (m *Module) GetOrganizations(ctx context.Context) ([]response.Organization, error) { return m.store.GetOrganizations(ctx) }
func (m *Module) GetPermissions(ctx context.Context) ([]response.Permission, error) { return m.store.GetPermissions(ctx) }
func (m *Module) GetMemberships(ctx context.Context) ([]response.Membership, error) { return m.store.GetMemberships(ctx) }
func (m *Module) GetTenants(ctx context.Context) ([]response.Tenant, error) { return m.store.GetTenants(ctx) }
func (m *Module) GetOAuthProviders(ctx context.Context, tenantID string) ([]response.OAuthProvider, error) {
	return m.store.GetOAuthProviders(ctx, tenantID)
}
func (m *Module) GetProjects(ctx context.Context, orgID string) ([]response.Project, error) { return m.store.GetProjects(ctx, orgID) }

func (m *Module) CreateTenant(ctx context.Context, name, slug, tenantType string) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil { return "", err }
	defer tx.Rollback(ctx)
	id, err := m.store.InsertTenant(ctx, tx, name, slug, tenantType)
	if err != nil { return "", err }
	return id, tx.Commit(ctx)
}

func (m *Module) UpdateRole(ctx context.Context, id, name, desc string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil { return err }
	defer tx.Rollback(ctx)
	if err := m.store.UpdateRole(ctx, tx, id, name, desc); err != nil { return err }
	return tx.Commit(ctx)
}

func (m *Module) DeleteRole(ctx context.Context, id string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil { return err }
	defer tx.Rollback(ctx)
	if err := m.store.DeleteRole(ctx, tx, id); err != nil { return err }
	return tx.Commit(ctx)
}

func (m *Module) ConfigureOAuth(ctx context.Context, tenantID, provider, clientID, clientSecret string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil { return err }
	defer tx.Rollback(ctx)
	if err := m.store.InsertOAuthProvider(ctx, tx, tenantID, provider, clientID, clientSecret); err != nil { return err }
	return tx.Commit(ctx)
}

func (m *Module) CreateProject(ctx context.Context, orgID, name string) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil { return "", err }
	defer tx.Rollback(ctx)
	id, err := m.store.InsertProject(ctx, tx, orgID, name)
	if err != nil { return "", err }
	return id, tx.Commit(ctx)
}
func (m *Module) UpdateProject(ctx context.Context, id, name string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil { return err }
	defer tx.Rollback(ctx)
	if err := m.store.UpdateProject(ctx, tx, id, name); err != nil { return err }
	return tx.Commit(ctx)
}

func (m *Module) DeleteProject(ctx context.Context, id string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil { return err }
	defer tx.Rollback(ctx)
	if err := m.store.DeleteProject(ctx, tx, id); err != nil { return err }
	return tx.Commit(ctx)
}

func (m *Module) GenerateResource(ctx context.Context, tenantID, resourceName string) (map[string]interface{}, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	slug := strings.ToLower(strings.ReplaceAll(resourceName, " ", ""))
	actions := []string{"read", "create", "update", "delete", "*"}
	var codes []string
	var adminPermIDs []string
	var viewerPermID string

	for _, action := range actions {
		code := slug + "." + action
		permID, err := m.store.InsertPermission(ctx, tx, slug, action, code, "Can "+action+" "+resourceName)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
		if action == "*" {
			adminPermIDs = append(adminPermIDs, permID)
		}
		if action == "read" {
			viewerPermID = permID
		}
	}

	adminRoleID, err := m.store.InsertSystemRole(ctx, tx, tenantID, resourceName+" Admin", "Full control over "+resourceName, false)
	if err != nil {
		return nil, err
	}
	viewerRoleID, err := m.store.InsertSystemRole(ctx, tx, tenantID, resourceName+" Viewer", "Read-only access to "+resourceName, false)
	if err != nil {
		return nil, err
	}

	for _, permID := range adminPermIDs {
		if err := m.store.InsertRolePerm(ctx, tx, adminRoleID, permID); err != nil {
			return nil, err
		}
	}
	if viewerPermID != "" {
		if err := m.store.InsertRolePerm(ctx, tx, viewerRoleID, viewerPermID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"message":     "Successfully generated identity model for " + resourceName,
		"permissions": codes,
		"roles":       []string{resourceName + " Admin", resourceName + " Viewer"},
	}, nil
}

func (m *Module) GetAuditLogs(ctx context.Context, tenantID, action string, limit, offset int) ([]response.AuditLog, error) {
	return m.store.GetAuditLogs(ctx, tenantID, action, limit, offset)
}

func (m *Module) GetApiKeys(ctx context.Context, tenantID string) ([]response.ApiKey, error) {
	return m.store.GetApiKeys(ctx, tenantID)
}

func (m *Module) CreateApiKey(ctx context.Context, tenantID, userID, name string, scopes []string) (map[string]interface{}, error) {
	rawKey := "aos_" + randomHex(24)
	keyHash := sha256Hex(rawKey)
	keyPrefix := rawKey
	if len(keyPrefix) > 12 {
		keyPrefix = keyPrefix[:12]
	}
	scopesJSON, _ := json.Marshal(scopes)
	key, _, err := m.store.CreateApiKey(ctx, tenantID, userID, name, keyPrefix, keyHash, scopesJSON)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"id":         key.ID,
		"name":       key.Name,
		"key_prefix": key.KeyPrefix,
		"scopes":     key.Scopes,
		"created_at": key.CreatedAt,
		"key":        rawKey,
	}, nil
}

func (m *Module) RevokeApiKey(ctx context.Context, keyID string) error {
	return m.store.RevokeApiKey(ctx, keyID)
}

func (m *Module) GetWebhooks(ctx context.Context, tenantID string) ([]response.Webhook, error) {
	return m.store.GetWebhooks(ctx, tenantID)
}

func (m *Module) CreateWebhook(ctx context.Context, tenantID, url string, events []string, createdBy string) (map[string]interface{}, error) {
	secret := randomHex(32)
	eventsJSON, _ := json.Marshal(events)
	hook, err := m.store.CreateWebhook(ctx, tenantID, url, secret, eventsJSON, createdBy)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"id":         hook.ID,
		"url":        hook.URL,
		"events":     hook.Events,
		"enabled":    hook.Enabled,
		"created_at": hook.CreatedAt,
		"secret":     secret,
	}, nil
}

func (m *Module) DeleteWebhook(ctx context.Context, id string) error {
	return m.store.DeleteWebhook(ctx, id)
}

func (m *Module) GetSecurityPolicies(ctx context.Context, tenantID, organizationID string) ([]response.SecurityPolicy, error) {
	return m.store.GetSecurityPolicies(ctx, tenantID, organizationID)
}

func (m *Module) CreateSecurityPolicy(ctx context.Context, tenantID, organizationID, name, policyType string, configuration map[string]interface{}) (*response.SecurityPolicy, error) {
	configJSON, _ := json.Marshal(configuration)
	return m.store.CreateSecurityPolicy(ctx, tenantID, organizationID, name, policyType, configJSON)
}

func (m *Module) DeleteSecurityPolicy(ctx context.Context, id string) error {
	return m.store.DeleteSecurityPolicy(ctx, id)
}

func (m *Module) GetDomains(ctx context.Context, tenantID string) ([]response.TenantDomain, error) {
	return m.store.GetTenantDomains(ctx, tenantID)
}

func (m *Module) RegisterDomain(ctx context.Context, tenantID, domain string) (map[string]interface{}, error) {
	token := "aos-domain-verification=" + randomHex(16)
	d, err := m.store.RegisterTenantDomain(ctx, tenantID, strings.ToLower(domain), token)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"id":         d.ID,
		"tenant_id":  d.TenantID,
		"domain":     d.Domain,
		"verified":   d.Verified,
		"created_at": d.CreatedAt,
		"dns_record": map[string]string{
			"type":  "TXT",
			"host":  "_aos-verify." + d.Domain,
			"value": token,
		},
	}, nil
}

func (m *Module) VerifyDomain(ctx context.Context, id string) (*response.TenantDomain, error) {
	return m.store.VerifyTenantDomain(ctx, id)
}

func (m *Module) DeleteDomain(ctx context.Context, id string) error {
	return m.store.DeleteTenantDomain(ctx, id)
}

func (m *Module) GetSsoConnections(ctx context.Context, orgID string) ([]response.SsoConnection, error) {
	return m.store.GetSsoConnections(ctx, orgID)
}

func (m *Module) CreateSsoConnection(ctx context.Context, orgID, provider, name, issuerURL, clientID, createdBy string) (*response.SsoConnection, error) {
	return m.store.CreateSsoConnection(ctx, orgID, provider, name, issuerURL, clientID, createdBy)
}

func (m *Module) UpdateSsoConnection(ctx context.Context, id string, enabled bool) error {
	return m.store.UpdateSsoConnectionEnabled(ctx, id, enabled)
}

func (m *Module) DeleteSsoConnection(ctx context.Context, id string) error {
	return m.store.DeleteSsoConnection(ctx, id)
}

func (m *Module) GetScimConnections(ctx context.Context, orgID string) ([]response.ScimConnection, error) {
	return m.store.GetScimConnections(ctx, orgID)
}

func (m *Module) CreateScimConnection(ctx context.Context, orgID, provider string) (map[string]interface{}, error) {
	token := "scim_" + randomHex(24)
	tokenHash := sha256Hex(token)
	conn, err := m.store.CreateScimConnection(ctx, orgID, provider, tokenHash)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"id":              conn.ID,
		"organization_id": conn.OrganizationID,
		"provider":        conn.Provider,
		"enabled":         conn.Enabled,
		"created_at":      conn.CreatedAt,
		"bearer_token":    token,
	}, nil
}

func (m *Module) RevokeScimConnection(ctx context.Context, id string) error {
	return m.store.RevokeScimConnection(ctx, id)
}

func (m *Module) GetNetworkRules(ctx context.Context, orgID string) ([]response.NetworkRule, error) {
	return m.store.GetNetworkRules(ctx, orgID)
}

func (m *Module) CreateNetworkRule(ctx context.Context, orgID, cidr, description string) (*response.NetworkRule, error) {
	return m.store.CreateNetworkRule(ctx, orgID, cidr, description)
}

func (m *Module) DeleteNetworkRule(ctx context.Context, id string) error {
	return m.store.DeleteNetworkRule(ctx, id)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
