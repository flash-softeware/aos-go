package response

import "time"

type User struct {
	ID        string `json:"id" db:"id"`
	Email     string `json:"email" db:"email"`
	FirstName string `json:"first_name" db:"first_name"`
	LastName  string `json:"last_name" db:"last_name"`
	Status    string `json:"status,omitempty" db:"status"`
}

type Role struct {
	ID          string `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`
	Description string `json:"description" db:"description"`
}

type Organization struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
	Slug string `json:"slug" db:"slug"`
}

type Permission struct {
	ID           string `json:"id" db:"id"`
	ResourceType string `json:"resource_type" db:"resource_type"`
	Action       string `json:"action" db:"action"`
	Code         string `json:"code" db:"code"`
	Description  string `json:"description,omitempty" db:"description"`
}

type Membership struct {
	ID           string `json:"id" db:"id"`
	UserID       string `json:"user_id" db:"user_id"`
	ResourceType string `json:"resource_type" db:"resource_type"`
	ResourceID   string `json:"resource_id" db:"resource_id"`
}

type UserOrganization struct {
	ID           string `json:"id" db:"id"`
	Name         string `json:"name" db:"name"`
	Slug         string `json:"slug" db:"slug"`
	MembershipID string `json:"membership_id" db:"membership_id"`
	RoleID       string `json:"role_id,omitempty" db:"role_id"`
	RoleName     string `json:"role_name,omitempty" db:"role_name"`
}

type OrgMember struct {
	UserID    string `json:"user_id" db:"user_id"`
	Email     string `json:"email" db:"email"`
	FirstName string `json:"first_name" db:"first_name"`
	LastName  string `json:"last_name" db:"last_name"`
	RoleName  string `json:"role_name,omitempty" db:"role_name"`
}

// PortalContext is returned at login and /v1/auth/me when organizations are enabled.
type PortalContext struct {
	TenantID            string             `json:"tenant_id,omitempty"`
	OrgID               string             `json:"org_id,omitempty"`
	RoleID              string             `json:"role_id,omitempty"`
	RoleName            string             `json:"role_name,omitempty"`
	Permissions         []string           `json:"permissions"`
	IsOrgAdmin          bool               `json:"is_org_admin"`
	NeedsOrgSelection   bool               `json:"needs_org_selection"`
	Organizations       []UserOrganization `json:"organizations"`
	ActiveOrganization  *UserOrganization  `json:"active_organization,omitempty"`
}

type Tenant struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
	Slug string `json:"slug" db:"slug"`
}

type OAuthProvider struct {
	ID       string `json:"id" db:"id"`
	Provider string `json:"provider" db:"provider"`
	ClientID string `json:"client_id" db:"client_id"`
}

type Project struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
}

type PasskeyUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PasskeyRP struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type PasskeyRegistrationOptions struct {
	Challenge string      `json:"challenge"`
	User      PasskeyUser `json:"user"`
	RP        PasskeyRP   `json:"rp"`
}

type PasskeyVerification struct {
	Verified bool `json:"verified"`
}

type Passkey struct {
	ID         string    `json:"id" db:"id"`
	DeviceType string    `json:"device_type,omitempty" db:"device_name"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

type PasskeyRecord struct {
	CredentialID   string `db:"credential_id"`
	PublicKey      string `db:"public_key"`
	SignCount      int64  `db:"sign_count"`
	DeviceName     string `db:"device_name"`
	BackupEligible bool   `db:"backup_eligible"`
	BackedUp       bool   `db:"backed_up"`
}

type UserSession struct {
	ID        string    `json:"id" db:"id"`
	IPAddress *string   `json:"ip_address,omitempty" db:"ip_address"`
	DeviceInfo any      `json:"device_info,omitempty" db:"device_info"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}

type AuditLog struct {
	ID           string    `json:"id" db:"id"`
	TenantID     *string   `json:"tenant_id,omitempty" db:"tenant_id"`
	UserID       *string   `json:"user_id,omitempty" db:"user_id"`
	Action       string    `json:"action" db:"action"`
	ResourceType *string   `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   *string   `json:"resource_id,omitempty" db:"resource_id"`
	Result       string    `json:"result" db:"result"`
	Details      any       `json:"details,omitempty" db:"details"`
	IPAddress    *string   `json:"ip_address,omitempty" db:"ip_address"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type ApiKey struct {
	ID         string     `json:"id" db:"id"`
	Name       string     `json:"name" db:"name"`
	KeyPrefix  string     `json:"key_prefix" db:"key_prefix"`
	Scopes     any        `json:"scopes" db:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

type Webhook struct {
	ID        string    `json:"id" db:"id"`
	URL       string    `json:"url" db:"url"`
	Events    any       `json:"events" db:"events"`
	Enabled   bool      `json:"enabled" db:"enabled"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type SecurityPolicy struct {
	ID             string  `json:"id" db:"id"`
	TenantID       *string `json:"tenant_id,omitempty" db:"tenant_id"`
	OrganizationID *string `json:"organization_id,omitempty" db:"organization_id"`
	Name           string  `json:"name" db:"name"`
	PolicyType     string  `json:"policy_type" db:"policy_type"`
	Configuration  any     `json:"configuration" db:"configuration"`
	Enabled        bool    `json:"enabled" db:"enabled"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type TenantDomain struct {
	ID         string     `json:"id" db:"id"`
	TenantID   string     `json:"tenant_id" db:"tenant_id"`
	Domain     string     `json:"domain" db:"domain"`
	Verified   bool       `json:"verified" db:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

type SsoConnection struct {
	ID             string  `json:"id" db:"id"`
	OrganizationID string  `json:"organization_id" db:"organization_id"`
	Provider       string  `json:"provider" db:"provider"`
	Name           string  `json:"name" db:"name"`
	Enabled        bool    `json:"enabled" db:"enabled"`
	IssuerURL      *string `json:"issuer_url,omitempty" db:"issuer_url"`
	MetadataURL    *string `json:"metadata_url,omitempty" db:"metadata_url"`
	ClientID       *string `json:"client_id,omitempty" db:"client_id"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type ScimConnection struct {
	ID             string     `json:"id" db:"id"`
	OrganizationID string     `json:"organization_id" db:"organization_id"`
	Provider       *string    `json:"provider,omitempty" db:"provider"`
	Enabled        bool       `json:"enabled" db:"enabled"`
	LastSyncAt     *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
}

type NetworkRule struct {
	ID             string  `json:"id" db:"id"`
	OrganizationID string  `json:"organization_id" db:"organization_id"`
	CIDR           string  `json:"cidr" db:"cidr"`
	Description    *string `json:"description,omitempty" db:"description"`
	Enabled        bool    `json:"enabled" db:"enabled"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}
