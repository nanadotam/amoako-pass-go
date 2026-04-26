package services

import (
	"context"
	"testing"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type stubUserStore struct {
	createFn             func(ctx context.Context, email, username, firstName, lastName, passwordHash string) (*repositories.User, error)
	findByEmailFn        func(ctx context.Context, email string) (*repositories.User, error)
	findByIDFn           func(ctx context.Context, userID string) (*repositories.User, error)
	updateLastLoginFn    func(ctx context.Context, userID string) error
	updatePasswordHashFn func(ctx context.Context, userID, passwordHash string) error
}

func (s stubUserStore) Create(ctx context.Context, email, username, firstName, lastName, passwordHash string) (*repositories.User, error) {
	return s.createFn(ctx, email, username, firstName, lastName, passwordHash)
}

func (s stubUserStore) FindByEmail(ctx context.Context, email string) (*repositories.User, error) {
	return s.findByEmailFn(ctx, email)
}

func (s stubUserStore) FindByID(ctx context.Context, userID string) (*repositories.User, error) {
	return s.findByIDFn(ctx, userID)
}

func (s stubUserStore) UpdateLastLogin(ctx context.Context, userID string) error {
	return s.updateLastLoginFn(ctx, userID)
}

func (s stubUserStore) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	return s.updatePasswordHashFn(ctx, userID, passwordHash)
}

type stubSessionStore struct {
	createFn        func(ctx context.Context, params repositories.SessionCreateParams) (*repositories.Session, error)
	findByTokenFn   func(ctx context.Context, token string) (*repositories.Session, error)
	revokeByTokenFn func(ctx context.Context, token string) error
	rotateFn        func(ctx context.Context, oldToken string, params repositories.SessionCreateParams) (*repositories.Session, error)
}

func (s stubSessionStore) Create(ctx context.Context, params repositories.SessionCreateParams) (*repositories.Session, error) {
	return s.createFn(ctx, params)
}

func (s stubSessionStore) FindByToken(ctx context.Context, token string) (*repositories.Session, error) {
	return s.findByTokenFn(ctx, token)
}

func (s stubSessionStore) RevokeByToken(ctx context.Context, token string) error {
	return s.revokeByTokenFn(ctx, token)
}

func (s stubSessionStore) Rotate(ctx context.Context, oldToken string, params repositories.SessionCreateParams) (*repositories.Session, error) {
	return s.rotateFn(ctx, oldToken, params)
}

func TestAuthServiceRegisterValidatesInput(t *testing.T) {
	service := NewAuthService(
		stubUserStore{},
		stubSessionStore{},
		nil,
		NewTokenService("secret", time.Hour),
		time.Hour,
		24*time.Hour,
		time.Second,
	)

	_, err := service.Register(context.Background(), RegisterInput{
		Email:    "bad-email",
		Username: "na",
		Password: "short",
	}, AuthMeta{})
	if err == nil {
		t.Fatal("Register() expected validation error")
	}
}

func TestAuthServiceLoginRejectsBadPassword(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	service := NewAuthService(
		stubUserStore{
			findByEmailFn: func(ctx context.Context, email string) (*repositories.User, error) {
				return &repositories.User{
					ID:           "user-1",
					Email:        email,
					Username:     "nana",
					PasswordHash: hash,
					CreatedAt:    time.Now(),
				}, nil
			},
			updateLastLoginFn: func(ctx context.Context, userID string) error {
				return nil
			},
		},
		stubSessionStore{
			createFn: func(ctx context.Context, params repositories.SessionCreateParams) (*repositories.Session, error) {
				return &repositories.Session{ID: "session-1", UserID: params.UserID, Token: params.Token}, nil
			},
		},
		nil,
		NewTokenService("secret", time.Hour),
		time.Hour,
		24*time.Hour,
		time.Second,
	)

	_, err = service.Login(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "wrong-password",
	}, AuthMeta{})
	if err == nil {
		t.Fatal("Login() expected invalid credentials error")
	}
}

func TestAuthServiceRefreshRotatesRefreshToken(t *testing.T) {
	var rotated bool
	service := NewAuthService(
		stubUserStore{
			findByIDFn: func(ctx context.Context, userID string) (*repositories.User, error) {
				return &repositories.User{
					ID:        userID,
					Email:     "user@example.com",
					Username:  "nana",
					CreatedAt: time.Now(),
				}, nil
			},
		},
		stubSessionStore{
			findByTokenFn: func(ctx context.Context, token string) (*repositories.Session, error) {
				return &repositories.Session{
					ID:        "session-1",
					UserID:    "user-1",
					Token:     token,
					ExpiresAt: time.Now().Add(time.Hour),
					IsActive:  true,
				}, nil
			},
			rotateFn: func(ctx context.Context, oldToken string, params repositories.SessionCreateParams) (*repositories.Session, error) {
				rotated = true
				return &repositories.Session{ID: "session-2", UserID: params.UserID, Token: params.Token}, nil
			},
		},
		nil,
		NewTokenService("secret", time.Hour),
		time.Hour,
		24*time.Hour,
		time.Second,
	)

	result, err := service.Refresh(context.Background(), RefreshInput{RefreshToken: "refresh-1"}, AuthMeta{})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !rotated {
		t.Fatal("Refresh() did not rotate session")
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("Refresh() returned empty tokens")
	}
}
