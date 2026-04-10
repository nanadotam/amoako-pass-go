package services

import (
	"bytes"
	"testing"
)

func TestEncryptionServiceRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	service := NewEncryptionService(key)

	cipherText, err := service.Encrypt("super-secret")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if cipherText == "super-secret" {
		t.Fatalf("Encrypt() returned plaintext")
	}

	plainText, err := service.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if plainText != "super-secret" {
		t.Fatalf("Decrypt() = %q, want %q", plainText, "super-secret")
	}
}
