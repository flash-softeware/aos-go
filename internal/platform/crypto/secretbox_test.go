package crypto

import "testing"

func TestSecretBoxRoundTrip(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	box, err := NewSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}

	secret := "JBSWY3DPEHPK3PXP"
	encrypted, err := box.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == secret {
		t.Fatal("expected encrypted value to differ from plaintext")
	}

	decrypted, err := box.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != secret {
		t.Fatalf("expected %q, got %q", secret, decrypted)
	}
}

func TestSecretBoxLegacyPlaintextPassthrough(t *testing.T) {
	box, err := NewSecretBox("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	plain := "JBSWY3DPEHPK3PXP"
	got, err := box.Decrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("expected legacy passthrough, got %q", got)
	}
}
