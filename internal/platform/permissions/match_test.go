package permissions

import "testing"

func TestMatches(t *testing.T) {
	tests := []struct {
		granted  string
		request  string
		expected bool
	}{
		{"*", "payment.refund", true},
		{"payment.*", "payment.read", true},
		{"payment.*", "payment.refund", true},
		{"payment.read", "payment.read", true},
		{"payment.read", "payment.refund", false},
		{"merchant.*", "merchant.user.invite", true},
		{"organization.*", "organization.read", true},
	}

	for _, tc := range tests {
		if got := Matches(tc.granted, tc.request); got != tc.expected {
			t.Fatalf("Matches(%q, %q) = %v, want %v", tc.granted, tc.request, got, tc.expected)
		}
	}
}
