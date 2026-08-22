package entities

type Session struct {
	ID               string
	UserID           string
	TokenHash        string
	ActiveResourceID string
	ExpiresAt        int64
}