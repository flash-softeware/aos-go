package entities

type AuthAccount struct {
	ID         string
	UserID     string
	Provider   string
	ProviderID string
	Token      string
	ExpiresAt  int64
}