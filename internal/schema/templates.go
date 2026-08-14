package schema

// Deprecated: tenant templates are no longer used by aos.Bootstrap.
// Business roles and permissions must be defined by the application developer.

type RoleDefinition struct {
	Name        string
	Description string
	IsSystem    bool
	Permissions []string
}

type TenantTemplate struct {
	Name             string
	HasOrganizations bool
	Roles            []RoleDefinition
}

var Templates = map[string]TenantTemplate{
	"SAAS_PLATFORM": {
		Name:             "SaaS Platform",
		HasOrganizations: true,
		Roles: []RoleDefinition{
			{
				Name:        "Platform Owner",
				Description: "Global Administrator for the Tenant",
				IsSystem:    true,
				Permissions: []string{"*"},
			},
			{
				Name:        "Merchant Admin",
				Description: "Organization administrator",
				IsSystem:    false,
				Permissions: []string{"organization.*", "member.*"},
			},
			{
				Name:        "Member",
				Description: "Basic Organization Member",
				IsSystem:    true,
				Permissions: []string{"user.read", "organization.read"},
			},
		},
	},
	"ENTERPRISE": {
		Name:             "Enterprise Application",
		HasOrganizations: false,
		Roles: []RoleDefinition{
			{
				Name:        "Global Admin",
				Description: "Full platform access",
				IsSystem:    true,
				Permissions: []string{"*"},
			},
			{
				Name:        "Department Admin",
				Description: "Department administrator",
				IsSystem:    false,
				Permissions: []string{"department.*"},
			},
			{
				Name:        "Employee",
				Description: "Standard employee",
				IsSystem:    false,
				Permissions: []string{"department.read"},
			},
		},
	},
	"CONSUMER_APP": {
		Name:             "Consumer Application",
		HasOrganizations: false,
		Roles: []RoleDefinition{
			{
				Name:        "App Admin",
				Description: "Full platform access",
				IsSystem:    true,
				Permissions: []string{"*"},
			},
			{
				Name:        "Support Agent",
				Description: "Customer support",
				IsSystem:    false,
				Permissions: []string{"user.read", "user.support"},
			},
			{
				Name:        "Customer",
				Description: "Standard customer",
				IsSystem:    false,
				Permissions: []string{"profile.*"},
			},
		},
	},
	"DEVELOPER_PLATFORM": {
		Name:             "Developer Platform",
		HasOrganizations: true,
		Roles: []RoleDefinition{
			{
				Name:        "Platform Admin",
				Description: "Full platform access",
				IsSystem:    true,
				Permissions: []string{"*"},
			},
			{
				Name:        "Developer",
				Description: "Project developer",
				IsSystem:    false,
				Permissions: []string{"project.*", "apikey.*"},
			},
		},
	},
	"IDENTITY_HUB": {
		Name:             "Identity Hub",
		HasOrganizations: true,
		Roles: []RoleDefinition{
			{
				Name:        "Global Admin",
				Description: "Full platform access",
				IsSystem:    true,
				Permissions: []string{"*"},
			},
		},
	},
}
