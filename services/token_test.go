package services

import (
	"testing"
	"time"
)

func TestTokenServiceGenerateAndParse(t *testing.T) {
	service := NewTokenService("test-secret", time.Hour)

	token, err := service.GenerateToken("user-123")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	userID, err := service.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}
	if userID != "user-123" {
		t.Fatalf("ParseToken() = %q, want %q", userID, "user-123")
	}
}

func TestTokenServiceRejectsInvalidToken(t *testing.T) {
	service := NewTokenService("test-secret", time.Hour)

	if _, err := service.ParseToken("not-a-token"); err == nil {
		t.Fatal("ParseToken() expected error for invalid token")
	}
}
