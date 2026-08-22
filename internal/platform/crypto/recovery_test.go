package crypto

import "testing"

func TestRecoveryCodeHashAndVerify(t *testing.T) {
	code := "ABCD-EFGH-IJKL"
	hash, err := HashRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRecoveryCode(code, hash) {
		t.Fatal("expected hashed code to verify")
	}
	if !VerifyRecoveryCode("abcd efgh ijkl", hash) {
		t.Fatal("expected normalized code to verify")
	}
	if VerifyRecoveryCode("WRONG-CODE-HERE", hash) {
		t.Fatal("expected wrong code to fail")
	}
}

func TestRecoveryCodeLegacyPlaintext(t *testing.T) {
	if !VerifyRecoveryCode("ABCD-EFGH", "ABCD-EFGH") {
		t.Fatal("expected legacy plaintext match")
	}
}
