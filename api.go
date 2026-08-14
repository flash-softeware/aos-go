package aos

import (
	"context"
	"errors"
	"net/http"

	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/module/auth"
	"github.com/aos/sdk-go/internal/module/iam"
	"github.com/aos/sdk-go/internal/module/membership"
	"github.com/aos/sdk-go/internal/module/organization"
	permModule "github.com/aos/sdk-go/internal/module/permissions"
	resModule "github.com/aos/sdk-go/internal/module/resources"
	userModule "github.com/aos/sdk-go/internal/module/user"
	"github.com/aos/sdk-go/internal/platform/events"
	"github.com/aos/sdk-go/internal/platform/identity"
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

// OrgIDFromContext is deprecated; use ActiveResourceIDFromContext.
func OrgIDFromContext(ctx context.Context) string {
	return identity.OrgIDFromContext(ctx)
}

func SessionFromContext(ctx context.Context) Session {
	s := identity.SessionFromContext(ctx)
	return Session{
		UserID:           s.UserID,
		TenantID:         s.TenantID,
		ActiveResourceID: s.OrgID,
		OrgID:            s.OrgID,
		RoleID:           s.RoleID,
	}
}

func (a *AOS) ContextWithSession(ctx context.Context, sess Session) context.Context {
	active := sess.ActiveResourceID
	if active == "" {
		active = sess.OrgID
	}
	return identity.WithSession(ctx, identity.Session{
		UserID:   sess.UserID,
		TenantID: sess.TenantID,
		OrgID:    active,
		RoleID:   sess.RoleID,
	})
}

type User = response.User

// Events returns the in-process event bus for application hooks.
func (a *AOS) Events() *events.Bus {
	return a.App.Events
}

type AuthAPI struct{ a *AOS }

func (a *AOS) Auth() *AuthAPI { return &AuthAPI{a: a} }

func (api *AuthAPI) SignUp(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	out, err := api.a.App.Users.Register(ctx, in.TenantID, userModule.RegisterInput{
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
	result, err := api.a.App.Auth.Login(ctx, email, password)
	if err != nil {
		return "", err
	}
	if result.MfaRequired {
		return "", errors.New("MFA required")
	}
	return result.SessionToken, nil
}

func (api *AuthAPI) Logout(ctx context.Context, sessionToken string) error {
	return api.a.App.Auth.Logout(ctx, sessionToken)
}

func (api *AuthAPI) ValidateSession(ctx context.Context, sessionToken string) (*Session, error) {
	s, err := api.a.App.Auth.ValidateSessionFull(ctx, sessionToken)
	if err != nil {
		return nil, err
	}
	return sessionFromAuth(s), nil
}

func (api *AuthAPI) CurrentUser(ctx context.Context, userID string) (*User, error) {
	return api.a.App.Auth.CurrentUser(ctx, userID)
}

func (api *AuthAPI) SetActiveResource(ctx context.Context, in SetContextInput) (*SetContextResult, error) {
	if err := api.a.App.Auth.SetActiveResource(ctx, in.SessionToken, in.ResourceID); err != nil {
		return nil, err
	}
	s, err := api.a.App.Auth.ValidateSessionFull(ctx, in.SessionToken)
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
	return api.a.App.Auth.SetActiveResource(ctx, sessionToken, orgID)
}

type AuthzAPI struct{ a *AOS }

func (a *AOS) Authz() *AuthzAPI { return &AuthzAPI{a: a} }

// IAM is deprecated; use Authz.
func (a *AOS) IAM() *AuthzAPI { return a.Authz() }

func (api *AuthzAPI) Can(ctx context.Context, in AuthzInput) (bool, error) {
	return api.a.App.IAM.Can(ctx, iam.CanParams{
		UserID:     in.UserID,
		ResourceID: in.ResourceID,
		Permission: in.Permission,
		TenantID:   in.TenantID,
	})
}

type RolesAPI struct{ a *AOS }

func (a *AOS) Roles() *RolesAPI { return &RolesAPI{a: a} }

func (api *RolesAPI) Create(ctx context.Context, in CreateRoleInput) (string, error) {
	return api.a.App.Roles.Create(ctx, in.TenantID, in.Name, in.Description, in.IsSystem)
}

func (api *RolesAPI) Grant(ctx context.Context, roleID, permissionCode string) error {
	return api.a.App.Roles.Grant(ctx, roleID, permissionCode)
}

func (api *RolesAPI) GetByName(ctx context.Context, tenantID, name string) (string, error) {
	return api.a.App.Store.GetRoleByNameCtx(ctx, tenantID, name)
}

type PermissionsAPI struct{ a *AOS }

func (a *AOS) Permissions() *PermissionsAPI { return &PermissionsAPI{a: a} }

func (api *PermissionsAPI) Register(ctx context.Context, in RegisterPermissionInput) (string, error) {
	return api.a.App.Permissions.Register(ctx, permModule.RegisterInput{
		Code:         in.Code,
		Description:  in.Description,
		ResourceType: in.ResourceType,
		Action:       in.Action,
	})
}

func (api *PermissionsAPI) RegisterMany(ctx context.Context, codes ...string) error {
	return api.a.App.Permissions.RegisterMany(ctx, codes...)
}

type ResourcesAPI struct{ a *AOS }

func (a *AOS) Resources() *ResourcesAPI { return &ResourcesAPI{a: a} }

func (api *ResourcesAPI) Create(ctx context.Context, in CreateResourceInput) (string, error) {
	return api.a.App.Resources.Create(ctx, resModule.CreateInput{
		TenantID:       in.TenantID,
		Type:           in.Type,
		ResourceID:     in.ResourceID,
		ParentResource: in.ParentResource,
		ParentType:     in.ParentType,
		Name:           in.Name,
	})
}

func (api *ResourcesAPI) IAMResourceID(ctx context.Context, resourceID, resourceType string) (string, error) {
	return api.a.App.Resources.IAMResourceID(ctx, resourceID, resourceType)
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
		return api.a.App.Memberships.Assign(ctx, add, in.IAMResource, in.RoleID)
	}
	return api.a.App.Memberships.Add(ctx, add)
}

func (api *MembershipsAPI) AssignRole(ctx context.Context, membershipID, iamResourceID, roleID string) error {
	return api.a.App.Memberships.AssignRole(ctx, membershipID, iamResourceID, roleID)
}

type OrganizationsAPI struct{ a *AOS }

func (a *AOS) Organizations() *OrganizationsAPI { return &OrganizationsAPI{a: a} }

func (api *OrganizationsAPI) Create(ctx context.Context, in CreateOrgInput) (string, error) {
	return api.a.App.Organizations.Create(ctx, in.TenantID, in.UserID, organization.CreateInput{Name: in.Name})
}

func (api *OrganizationsAPI) Invite(ctx context.Context, tenantID, orgID, email, roleID string) (*organization.InviteResult, error) {
	return api.a.App.Organizations.Invite(ctx, tenantID, orgID, email, roleID)
}

type MiddlewareAPI struct{ a *AOS }

func (a *AOS) Middleware() *MiddlewareAPI { return &MiddlewareAPI{a: a} }

func (m *MiddlewareAPI) RequireSession() func(http.Handler) http.Handler {
	return m.a.App.AuthMiddleware.RequireSession
}

func (m *MiddlewareAPI) OptionalSession() func(http.Handler) http.Handler {
	return m.a.App.AuthMiddleware.OptionalSession
}

func (m *MiddlewareAPI) RequirePermission(permission string) func(http.Handler) http.Handler {
	a := m.a
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userID := identity.UserIDFromContext(ctx)
			if userID == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			resourceID := r.URL.Query().Get("resourceId")
			if resourceID == "" {
				resourceID = identity.OrgIDFromContext(ctx)
			}
			if resourceID == "" {
				resourceID = identity.TenantIDFromContext(ctx)
			}
			if resourceID == "" {
				http.Error(w, "missing resource scope", http.StatusBadRequest)
				return
			}

			allowed, err := a.Authz().Can(ctx, AuthzInput{
				UserID:     userID,
				ResourceID: resourceID,
				Permission: permission,
				TenantID:   identity.TenantIDFromContext(ctx),
			})
			if err != nil || !allowed {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func sessionFromAuth(s *auth.Session) *Session {
	return &Session{
		UserID:           s.UserID,
		TenantID:         s.TenantID,
		ActiveResourceID: s.ActiveResourceID,
		OrgID:            s.OrgID,
		RoleID:           s.RoleID,
	}
}
