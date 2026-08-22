package identity

import "context"

type contextKey string

const (
	keyUserID              contextKey = "aos_user_id"
	keyTenantID            contextKey = "aos_tenant_id"
	keyOrgID               contextKey = "aos_org_id"
	keyActiveResourceIAMID contextKey = "aos_active_resource_iam_id"
	keyRoleID              contextKey = "aos_role_id"
)

// Session holds validated identity context for a request.
type Session struct {
	UserID              string
	TenantID            string
	OrgID               string // business organization UUID
	ActiveResourceIAMID string // iam_resources.id for authorization scope
	RoleID              string
}

func WithSession(ctx context.Context, s Session) context.Context {
	ctx = context.WithValue(ctx, keyUserID, s.UserID)
	if s.TenantID != "" {
		ctx = context.WithValue(ctx, keyTenantID, s.TenantID)
	}
	if s.OrgID != "" {
		ctx = context.WithValue(ctx, keyOrgID, s.OrgID)
	}
	if s.ActiveResourceIAMID != "" {
		ctx = context.WithValue(ctx, keyActiveResourceIAMID, s.ActiveResourceIAMID)
	}
	if s.RoleID != "" {
		ctx = context.WithValue(ctx, keyRoleID, s.RoleID)
	}
	return ctx
}

func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyUserID).(string)
	return v
}

func TenantIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyTenantID).(string)
	return v
}

func OrgIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyOrgID).(string)
	return v
}

func ActiveResourceIAMIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyActiveResourceIAMID).(string)
	return v
}

func RoleIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyRoleID).(string)
	return v
}

func SessionFromContext(ctx context.Context) Session {
	return Session{
		UserID:              UserIDFromContext(ctx),
		TenantID:            TenantIDFromContext(ctx),
		OrgID:               OrgIDFromContext(ctx),
		ActiveResourceIAMID: ActiveResourceIAMIDFromContext(ctx),
		RoleID:              RoleIDFromContext(ctx),
	}
}
