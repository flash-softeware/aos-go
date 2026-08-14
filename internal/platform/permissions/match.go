package permissions

import "strings"

// Matches reports whether granted satisfies requested using AOS wildcard rules:
//
//   - * grants everything
//   - prefix.* grants prefix.action and prefix.sub.action
//   - exact code match
func Matches(granted, requested string) bool {
	if granted == "*" || granted == requested {
		return true
	}
	if strings.HasSuffix(granted, ".*") {
		prefix := strings.TrimSuffix(granted, ".*")
		if prefix == "" {
			return true
		}
		return requested == prefix || strings.HasPrefix(requested, prefix+".")
	}
	return false
}
