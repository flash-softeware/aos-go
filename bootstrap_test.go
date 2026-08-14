package aos_test

import (
	"testing"

	"github.com/aos/sdk-go/internal/platform/permissions"
)

func TestPermissionWildcardsDocumented(t *testing.T) {
	cases := []struct {
		granted  string
		request  string
		expected bool
	}{
		{"*", "payment.refund", true},
		{"payment.*", "payment.read", true},
		{"payment.*", "payment.refund", true},
		{"payment.read", "payment.read", true},
		{"payment.read", "payment.refund", false},
	}

	for _, tc := range cases {
		if got := permissions.Matches(tc.granted, tc.request); got != tc.expected {
			t.Fatalf("Matches(%q,%q)=%v want %v", tc.granted, tc.request, got, tc.expected)
		}
	}
}
