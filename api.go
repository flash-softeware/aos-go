package aos

import (
	"context"
	"net/http"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/auth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/iam"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/membership"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/organization"
	permModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/permissions"
	resModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/resources"
	rolesModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/roles"
	userModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/user"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
	platformmiddleware "github.com/Esubalew-Sintie/aos-auth-go/internal/platform/middleware"
)

func UserIDFromContext(ctx context.Context) string {
	return identity.UserIDFromContext(ctx)
}

func TenantIDFromContext(ctx context.Context) string {
	return identity.TenantIDFromContext(ctx)
}

func ActiveResourceIDFromContext(ctx context.Context) string {
	return identity.OrgIDFromContext(ctx)
}

func ActiveResourceIAMIDFromContext(ctx context.Context) string {
	return identity.ActiveResourceIAMIDFromContext(ctx)
}

// OrgIDFromContext is deprecated; use ActiveResourceIDFromContext.
func OrgIDFromContext(ctx context.Context) string {
	return identity.OrgIDFromContext(ctx)
}

func SessionFromContext(ctx context.Context) Session {
	s := identity.SessionFromContext(ctx)
	return Session{
		UserID:              s.UserID,
		TenantID:            s.TenantID,
		ActiveResourceID:    s.OrgID,
		ActiveResourceIAMID: s.ActiveResourceIAMID,
		OrgID:               s.OrgID,
		RoleID:              s.RoleID,
	}
}

func (a *AOS) ContextWithSession(ctx context.Context, sess Session) context.Context {
	active := sess.ActiveResourceID
	if active == "" {
		active = sess.OrgID
	}
	return identity.WithSession(ctx, identity.Session{
		UserID:              sess.UserID,
		TenantID:            sess.TenantID,
		OrgID:               active,
		ActiveResourceIAMID: sess.ActiveResourceIAMID,
		RoleID:              sess.RoleID,
	})
}

type User = response.User

// Events returns the in-process event bus for application hooks.
func (a *AOS) Events() *events.Bus {
	return a.app.Events
}

type AuthAPI struct{ a *AOS }

func (a *AOS) Auth() *AuthAPI { return &AuthAPI{a: a} }

func (api *AuthAPI) SignUp(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	out, err := api.a.app.Users.Register(ctx, in.TenantID, userModule.RegisterInput{
		Email:     in.Email,
		Password:  in.Password,
		FirstName: in.FirstName,
		LastName:  in.LastName,
	})
	if err != nil {
		return nil, err
	}
	return &RegisterOutput{
		UserID:       out.UserID,
		SessionToken: out.SessionToken,
		Email:        out.Email,
	}, nil
}

func (api *AuthAPI) Login(ctx context.Context, email, password string) (string, error) {
	result, err := api.a.app.Auth.Login(ctx, email, password)
	if err != nil {
		return "", err
	}
	if result.MfaRequired {
		return "", aoserrors.ErrMfaRequired
	}
	return result.SessionToken, nil
}

func (api *AuthAPI) Logout(ctx context.Context, sessionToken string) error {
	return api.a.app.Auth.Logout(ctx, sessionToken)
}

func (api *AuthAPI) ValidateSession(ctx context.Context, sessionToken string) (*Session, error) {
	s, err := api.a.app.Auth.ValidateSessionFull(ctx, sessionToken)
	if err != nil {
		return nil, err
	}
	return sessionFromAuth(s), nil
}

func (api *AuthAPI) CurrentUser(ctx context.Context, userID string) (*User, error) {
	return api.a.app.Auth.CurrentUser(ctx, userID)
}

func (api *AuthAPI) SetActiveResource(ctx context.Context, in SetContextInput) (*SetContextResult, error) {
	if err := api.a.app.Auth.SetActiveResource(ctx, in.SessionToken, in.ResourceID); err != nil {
		return nil, err
	}
	s, err := api.a.app.Auth.ValidateSessionFull(ctx, in.SessionToken)
	if err != nil {
		return nil, err
	}
	return &SetContextResult{
		ActiveResourceID: s.ActiveResourceID,
		RoleID:           s.RoleID,
	}, nil
}

// SwitchOrganization is deprecated; use SetActiveResource.
func (api *AuthAPI) SwitchOrganization(ctx context.Context, sessionToken, orgID string) error {
	return api.a.app.Auth.SetActiveResource(ctx, sessionToken, orgID)
}

type AuthzAPI struct{ a *AOS }

func (a *AOS) Authz() *AuthzAPI { return &AuthzAPI{a: a} }

// IAM is deprecated; use Authz.
func (a *AOS) IAM() *AuthzAPI { return a.Authz() }

func (api *AuthzAPI) Can(ctx context.Context, in AuthzInput) (bool, error) {
	return api.a.app.IAM.Can(ctx, iam.CanParams{
		UserID:     in.UserID,
		ResourceID: in.ResourceID,
		Permission: in.Permission,
		TenantID:   in.TenantID,
	})
}

type RolesAPI struct{ a *AOS }

func (a *AOS) Roles() *RolesAPI { return &RolesAPI{a: a} }

func (api *RolesAPI) Create(ctx context.Context, in CreateRoleInput) (string, error) {
	return api.a.app.Roles.Create(ctx, rolesModule.CreateInput{
		Name:                   in.Name,
		Description:            in.Description,
		IsSystem:               in.IsSystem,
		OrganizationBusinessID: in.OrganizationID,
	})
}

func (api *RolesAPI) Grant(ctx context.Context, roleID, permissionCode string) error {
	return api.a.app.Roles.Grant(ctx, roleID, permissionCode)
}

func (api *RolesAPI) GetByName(ctx context.Context, tenantID, name string) (string, error) {
	_ = tenantID
	role, err := api.a.app.Store.Roles().GetByName(ctx, name)
	if err != nil {
		return "", err
	}
	return role.ID, nil
}

type PermissionsAPI struct{ a *AOS }

func (a *AOS) Permissions() *PermissionsAPI { return &PermissionsAPI{a: a} }

func (api *PermissionsAPI) Register(ctx context.Context, in RegisterPermissionInput) (string, error) {
	return api.a.app.Permissions.Register(ctx, permModule.RegisterInput{
		Code:         in.Code,
		Description:  in.Description,
		ResourceType: in.ResourceType,
		Action:       in.Action,
	})
}

func (api *PermissionsAPI) RegisterMany(ctx context.Context, codes ...string) error {
	return api.a.app.Permissions.RegisterMany(ctx, codes...)
}

type ResourcesAPI struct{ a *AOS }

func (a *AOS) Resources() *ResourcesAPI { return &ResourcesAPI{a: a} }

func (api *ResourcesAPI) Create(ctx context.Context, in CreateResourceInput) (string, error) {
	return api.a.app.Resources.Create(ctx, resModule.CreateInput{
		TenantID:       in.TenantID,
		Type:           in.Type,
		ResourceID:     in.ResourceID,
		ParentResource: in.ParentResource,
		ParentType:     in.ParentType,
		Name:           in.Name,
	})
}

func (api *ResourcesAPI) IAMResourceID(ctx context.Context, resourceID, resourceType string) (string, error) {
	return api.a.app.Resources.IAMResourceID(ctx, resourceID, resourceType)
}

type MembershipsAPI struct{ a *AOS }

func (a *AOS) Memberships() *MembershipsAPI { return &MembershipsAPI{a: a} }

func (api *MembershipsAPI) Add(ctx context.Context, in AddMembershipInput) (string, error) {
	add := membership.AddInput{
		TenantID:     in.TenantID,
		UserID:       in.UserID,
		ResourceType: in.ResourceType,
		ResourceID:   in.ResourceID,
	}
	if in.RoleID != "" && in.IAMResource != "" {
		return api.a.app.Memberships.Assign(ctx, add, in.IAMResource, in.RoleID)
	}
	return api.a.app.Memberships.Add(ctx, add)
}

func (api *MembershipsAPI) AssignRole(ctx context.Context, membershipID, iamResourceID, roleID string) error {
	return api.a.app.Memberships.AssignRole(ctx, membershipID, iamResourceID, roleID)
}

type OrganizationsAPI struct{ a *AOS }

func (a *AOS) Organizations() *OrganizationsAPI { return &OrganizationsAPI{a: a} }

func (api *OrganizationsAPI) Create(ctx context.Context, in CreateOrgInput) (string, error) {
	userID := in.UserID
	if userID == "" {
		return "", aoserrors.ErrUserIDRequired
	}
	return api.a.app.Organizations.Create(ctx, userID, in.SessionToken, organization.CreateInput{Name: in.Name})
}

func (api *OrganizationsAPI) Invite(ctx context.Context, tenantID, orgID, email, roleID string) (*organization.InviteResult, error) {
	return api.a.app.Organizations.Invite(ctx, tenantID, orgID, email, roleID)
}

func (api *OrganizationsAPI) Activate(ctx context.Context, userID, sessionToken, orgBusinessID string) error {
	return api.a.app.Organizations.Activate(ctx, userID, sessionToken, orgBusinessID)
}

type MiddlewareAPI struct{ a *AOS }

func (a *AOS) Middleware() *MiddlewareAPI { return &MiddlewareAPI{a: a} }

func (m *MiddlewareAPI) RequireSession() func(http.Handler) http.Handler {
	return m.a.app.AuthMiddleware.RequireSession
}

func (m *MiddlewareAPI) OptionalSession() func(http.Handler) http.Handler {
	return m.a.app.AuthMiddleware.OptionalSession
}

func (m *MiddlewareAPI) RequirePermission(permission string) func(http.Handler) http.Handler {
	a := m.a
	orgsEnabled := a.app.Auth.OrganizationsEnabled()
	canFn := platformmiddleware.CanFunc(func(ctx context.Context, userID, resourceID, perm, tenantID string) (bool, error) {
		return a.Authz().Can(ctx, AuthzInput{
			UserID:     userID,
			ResourceID: resourceID,
			Permission: perm,
			TenantID:   tenantID,
		})
	})
	return platformmiddleware.RequirePermission(canFn, permission, orgsEnabled)
}

func sessionFromAuth(s *auth.Session) *Session {
	return &Session{
		UserID:              s.UserID,
		TenantID:            s.TenantID,
		ActiveResourceID:    s.ActiveOrganizationID,
		ActiveResourceIAMID: s.ActiveResourceIAMID,
		OrgID:               s.ActiveOrganizationID,
		RoleID:              s.RoleID,
	}
}
