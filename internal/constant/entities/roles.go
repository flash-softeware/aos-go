package entities

type Role struct {
	ID                string
	OrganizationID    string // iam_resources.id; empty = system role
	Name              string
	Description       string
	IsSystem          bool
	HasAllPermissions bool
}