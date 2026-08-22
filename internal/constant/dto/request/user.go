package request

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	TenantID  string `json:"tenantId"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type CreateOrgRequest struct {
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	Name     string `json:"name"`
}

type CreateRoleRequest struct {
	TenantID       string `json:"tenantId"`
	OrganizationID string `json:"organizationId"`
	OrganizationIDSnake string `json:"organization_id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	IsSystem       bool   `json:"isSystem"`
}

type IAMCanRequest struct {
	UserID     string `json:"userId"`
	ResourceID string `json:"resourceId"`
	Permission string `json:"permission"`
	TenantID   string `json:"tenantId"`
}

type MeCanRequest struct {
	ResourceID string `json:"resource_id"`
	Permission string `json:"permission"`
}

type SetContextRequest struct {
	ResourceID     string `json:"resource_id"`
	OrganizationID string `json:"organization_id"`
}
