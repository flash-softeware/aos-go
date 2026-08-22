package management

import (
	"context"
	"strings"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	rolesModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/roles"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)


type Module struct {
	store storage.Storage
	roles *rolesModule.Module
}

func New(store storage.Storage, roles *rolesModule.Module) *Module {
	return &Module{store: store, roles: roles}
}

func (m *Module) CreateRole(ctx context.Context, name, description, organizationBusinessID string, isSystem bool) (string, error) {
	return m.roles.Create(ctx, rolesModule.CreateInput{
		Name:                   name,
		Description:            description,
		IsSystem:               isSystem,
		OrganizationBusinessID: organizationBusinessID,
	})
}

func (m *Module) RolesOrganizationsEnabled() bool {
	return m.roles.OrganizationsEnabled()
}

func (m *Module) CreatePermission(ctx context.Context, resourceType, action, code, description string) (string, error) {
	_ = resourceType
	_ = action
	permID := uuid.New().String()
	err := m.store.Permissions().Create(ctx, &entities.Permission{
		ID:          permID,
		Code:        code,
		Description: description,
	})
	return permID, err
}

func (m *Module) GetRolePermissionIDs(ctx context.Context, roleID string) ([]string, error) {
	_ = roleID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) ReplaceRolePermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	_ = roleID
	_ = permissionIDs
	return aoserrors.ErrNotSupported
}

func (m *Module) AssignUserRole(ctx context.Context, membershipID, resourceID, roleID string) error {
	return m.store.Memberships().AssignRole(ctx, membershipID, resourceID, roleID)
}

func (m *Module) GetUsers(ctx context.Context) ([]response.User, error) {
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) GetRoles(ctx context.Context) ([]response.Role, error) {
	roles, err := m.store.Roles().List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]response.Role, 0, len(roles))
	for _, r := range roles {
		out = append(out, response.Role{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
		})
	}
	return out, nil
}

func (m *Module) GetOrganizations(ctx context.Context) ([]response.Organization, error) {
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) GetPermissions(ctx context.Context) ([]response.Permission, error) {
	perms, err := m.store.Permissions().List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]response.Permission, 0, len(perms))
	for _, p := range perms {
		out = append(out, response.Permission{
			ID:          p.ID,
			Code:        p.Code,
			Description: p.Description,
		})
	}
	return out, nil
}

func (m *Module) GetMemberships(ctx context.Context) ([]response.Membership, error) {
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) GetTenants(ctx context.Context) ([]response.Tenant, error) {
	return []response.Tenant{}, nil
}

func (m *Module) GetOAuthProviders(ctx context.Context, tenantID string) ([]response.OAuthProvider, error) {
	_ = tenantID
	return []response.OAuthProvider{}, nil
}

func (m *Module) GetProjects(ctx context.Context, orgID string) ([]response.Project, error) {
	_ = orgID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) CreateTenant(ctx context.Context, name, slug, tenantType string) (string, error) {
	_ = name
	_ = slug
	_ = tenantType
	return "", aoserrors.ErrNotSupported
}

func (m *Module) UpdateRole(ctx context.Context, id, name, desc string) error {
	_ = id
	_ = name
	_ = desc
	return aoserrors.ErrNotSupported
}

func (m *Module) DeleteRole(ctx context.Context, id string) error {
	return m.store.Roles().Delete(ctx, id)
}

func (m *Module) ConfigureOAuth(ctx context.Context, tenantID, provider, clientID, clientSecret string) error {
	_ = tenantID
	_ = provider
	_ = clientID
	_ = clientSecret
	return aoserrors.ErrNotSupported
}

func (m *Module) CreateProject(ctx context.Context, orgID, name string) (string, error) {
	_ = orgID
	_ = name
	return "", aoserrors.ErrNotSupported
}

func (m *Module) UpdateProject(ctx context.Context, id, name string) error {
	_ = id
	_ = name
	return aoserrors.ErrNotSupported
}

func (m *Module) DeleteProject(ctx context.Context, id string) error {
	_ = id
	return aoserrors.ErrNotSupported
}

func (m *Module) GenerateResource(ctx context.Context, tenantID, resourceName string) (map[string]interface{}, error) {
	if m.roles.OrganizationsEnabled() {
		return nil, aoserrors.ErrOrganizationScopeNotAllowed
	}
	_ = tenantID

	slug := strings.ToLower(strings.ReplaceAll(resourceName, " ", ""))
	actions := []string{"read", "create", "update", "delete", "*"}
	var codes []string
	var adminPermIDs []string
	var viewerPermID string

	err := m.store.Transaction(ctx, func(tx storage.Storage) error {
		for _, action := range actions {
			code := slug + "." + action
			permID := uuid.New().String()
			if err := tx.Permissions().Create(ctx, &entities.Permission{
				ID:           permID,
				Code:         code,
				Description:  "Can " + action + " " + resourceName,
				ResourceType: slug,
				Action:       action,
			}); err != nil {
				return err
			}
			codes = append(codes, code)
			if action == "*" {
				adminPermIDs = append(adminPermIDs, permID)
			}
			if action == "read" {
				viewerPermID = permID
			}
		}

		adminRoleID := uuid.New().String()
		if err := tx.Roles().Create(ctx, &entities.Role{
			ID:          adminRoleID,
			Name:        resourceName + " Admin",
			Description: "Full control over " + resourceName,
		}); err != nil {
			return err
		}

		viewerRoleID := uuid.New().String()
		if err := tx.Roles().Create(ctx, &entities.Role{
			ID:          viewerRoleID,
			Name:        resourceName + " Viewer",
			Description: "Read-only access to " + resourceName,
		}); err != nil {
			return err
		}

		for _, permID := range adminPermIDs {
			_ = permID
			code := slug + ".*"
			if _, err := tx.Roles().GrantPermission(ctx, adminRoleID, code); err != nil {
				return err
			}
		}
		if viewerPermID != "" {
			_ = viewerPermID
			if _, err := tx.Roles().GrantPermission(ctx, viewerRoleID, slug+".read"); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"message":     "Successfully generated identity model for " + resourceName,
		"permissions": codes,
		"roles":       []string{resourceName + " Admin", resourceName + " Viewer"},
	}, nil
}

func (m *Module) GetAuditLogs(ctx context.Context, tenantID, action string, limit, offset int) ([]response.AuditLog, error) {
	return m.store.Audit().List(ctx, tenantID, action, limit, offset)
}

func (m *Module) GetApiKeys(ctx context.Context, tenantID string) ([]response.ApiKey, error) {
	_ = tenantID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) CreateApiKey(ctx context.Context, tenantID, userID, name string, scopes []string) (map[string]interface{}, error) {
	_ = tenantID
	_ = userID
	_ = name
	_ = scopes
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) RevokeApiKey(ctx context.Context, keyID string) error {
	_ = keyID
	return aoserrors.ErrNotSupported
}

func (m *Module) GetWebhooks(ctx context.Context, tenantID string) ([]response.Webhook, error) {
	_ = tenantID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) CreateWebhook(ctx context.Context, tenantID, url string, events []string, createdBy string) (map[string]interface{}, error) {
	_ = tenantID
	_ = url
	_ = events
	_ = createdBy
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) DeleteWebhook(ctx context.Context, id string) error {
	_ = id
	return aoserrors.ErrNotSupported
}

func (m *Module) GetSecurityPolicies(ctx context.Context, tenantID, organizationID string) ([]response.SecurityPolicy, error) {
	_ = tenantID
	_ = organizationID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) CreateSecurityPolicy(ctx context.Context, tenantID, organizationID, name, policyType string, configuration map[string]interface{}) (*response.SecurityPolicy, error) {
	_ = tenantID
	_ = organizationID
	_ = name
	_ = policyType
	_ = configuration
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) DeleteSecurityPolicy(ctx context.Context, id string) error {
	_ = id
	return aoserrors.ErrNotSupported
}

func (m *Module) GetDomains(ctx context.Context, tenantID string) ([]response.TenantDomain, error) {
	_ = tenantID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) RegisterDomain(ctx context.Context, tenantID, domain string) (map[string]interface{}, error) {
	_ = tenantID
	_ = domain
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) VerifyDomain(ctx context.Context, id string) (*response.TenantDomain, error) {
	_ = id
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) DeleteDomain(ctx context.Context, id string) error {
	_ = id
	return aoserrors.ErrNotSupported
}

func (m *Module) GetSsoConnections(ctx context.Context, orgID string) ([]response.SsoConnection, error) {
	_ = orgID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) CreateSsoConnection(ctx context.Context, orgID, provider, name, issuerURL, clientID, createdBy string) (*response.SsoConnection, error) {
	_ = orgID
	_ = provider
	_ = name
	_ = issuerURL
	_ = clientID
	_ = createdBy
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) UpdateSsoConnection(ctx context.Context, id string, enabled bool) error {
	_ = id
	_ = enabled
	return aoserrors.ErrNotSupported
}

func (m *Module) DeleteSsoConnection(ctx context.Context, id string) error {
	_ = id
	return aoserrors.ErrNotSupported
}

func (m *Module) GetScimConnections(ctx context.Context, orgID string) ([]response.ScimConnection, error) {
	_ = orgID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) CreateScimConnection(ctx context.Context, orgID, provider string) (map[string]interface{}, error) {
	_ = orgID
	_ = provider
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) RevokeScimConnection(ctx context.Context, id string) error {
	_ = id
	return aoserrors.ErrNotSupported
}

func (m *Module) GetNetworkRules(ctx context.Context, orgID string) ([]response.NetworkRule, error) {
	_ = orgID
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) CreateNetworkRule(ctx context.Context, orgID, cidr, description string) (*response.NetworkRule, error) {
	_ = orgID
	_ = cidr
	_ = description
	return nil, aoserrors.ErrNotSupported
}

func (m *Module) DeleteNetworkRule(ctx context.Context, id string) error {
	_ = id
	return aoserrors.ErrNotSupported
}
