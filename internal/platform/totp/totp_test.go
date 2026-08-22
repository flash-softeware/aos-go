package totp

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateSecretAndVerifyRoundTrip(t *testing.T) {
	secret, err := GenerateSecret(20)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}

	code, err := GenerateTOTP(secret, 0)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
	if !VerifyTOTP(secret, code, 0) {
		t.Fatal("expected current-step code to verify")
	}
}

func TestDecodeBase32RejectsInvalidCharacter(t *testing.T) {
	_, err := DecodeBase32("ABC!DEF")
	if err == nil {
		t.Fatal("expected error for invalid base32 character")
	}
}

func TestVerifyTOTPAcceptsAdjacentWindow(t *testing.T) {
	secret, err := GenerateSecret(20)
	if err != nil {
		t.Fatal(err)
	}

	step := time.Now().Unix()/30 - 1
	code, err := GenerateTOTP(secret, step)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, code, 1) {
		t.Fatal("expected previous-window code to verify with window=1")
	}
}

func TestRandomRecoveryCodesFormat(t *testing.T) {
	codes, err := RandomRecoveryCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 3 {
		t.Fatalf("expected 3 codes, got %d", len(codes))
	}
	for _, c := range codes {
		if !strings.Contains(c, "-") {
			t.Fatalf("expected dashed format, got %q", c)
		}
	}
}
