package entities

type Invitation struct {
	ID           string
	Email        string
	ResourceType string
	ResourceID   string
	RoleID       string
	InvitedBy    string
	Status       string
	ExpiresAt    int64
}