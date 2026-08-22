package aos

// Session represents validated identity for a request or programmatic call.
type Session struct {
	UserID              string
	TenantID            string
	ActiveResourceID    string // business organization UUID when orgs are enabled
	ActiveResourceIAMID string // iam_resources.id — authorization scope
	RoleID              string
	// OrgID is deprecated; use ActiveResourceID.
	OrgID string
}

// AuthzInput describes an authorization check.
type AuthzInput struct {
	UserID     string
	ResourceID string
	Permission string
	TenantID   string
}

// CanInput is deprecated; use AuthzInput.
type CanInput = AuthzInput

// BootstrapInput configures first-time platform setup.
type BootstrapInput struct {
	TenantName     string
	OrgName        string
	WithDefaultOrg bool
	Owner          BootstrapOwner
	// TenantType is deprecated and ignored.
	TenantType string
}

type BootstrapOwner struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

// BootstrapResult is returned after successful bootstrap.
type BootstrapResult struct {
	Message      string
	TenantID     string
	UserID       string
	SessionToken string
	OrgID        string
}

// GenerateResourceResult describes seeded business permissions.
type GenerateResourceResult struct {
	Message     string
	Permissions []string
	Roles       []string
}

type CreateOrgInput struct {
	TenantID     string // deprecated; ignored for embedded installs
	UserID       string
	SessionToken string
	Name         string
}

type RegisterInput struct {
	TenantID  string
	Email     string
	Password  string
	FirstName string
	LastName  string
}

type RegisterOutput struct {
	UserID       string
	SessionToken string
	Email        string
}

type CreateResourceInput struct {
	TenantID       string
	Type           string
	ResourceID     string
	ParentResource string
	ParentType     string
	Name           string
}

type AddMembershipInput struct {
	TenantID     string
	UserID       string
	ResourceType string
	ResourceID   string
	RoleID       string
	IAMResource  string
}

type CreateRoleInput struct {
	Name           string
	Description    string
	IsSystem       bool
	OrganizationID string // business org UUID; empty creates a system/global role
	// TenantID is deprecated and ignored.
	TenantID string
}

type RegisterPermissionInput struct {
	Code         string
	Description  string
	ResourceType string
	Action       string
}

type SetContextInput struct {
	SessionToken string
	ResourceID   string
}

type SetContextResult struct {
	ActiveResourceID string
	RoleID           string
}
