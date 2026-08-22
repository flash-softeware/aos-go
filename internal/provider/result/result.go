package result

// Auth holds session + user identity returned by auth providers.
type Auth struct {
	SessionToken string
	UserID       string
	MfaRequired  bool
	MfaToken     string
}
