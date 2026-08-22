package provider

// Provider authenticates users. See password and oauth subpackages.
type Provider interface {
	Name() string
}
