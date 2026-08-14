package aos

import "strings"

// ParseWebAuthnOrigins splits a comma-separated list of allowed WebAuthn origins.
// An empty string returns nil so the SDK applies its localhost defaults.
func ParseWebAuthnOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		if origin := strings.TrimSpace(part); origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}
