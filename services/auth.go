package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

var ErrInvalidCredentials = errors.New("invalid email or password")
var ErrInvalidAuthPayload = errors.New("invalid auth payload")
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

type AuthService struct {
	users           userStore
	sessions        sessionStore
	tokens          *TokenService
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	requestTimeout  time.Duration
}

type userStore interface {
	Create(ctx context.Context, email, username, passwordHash string) (*repositories.User, error)
	FindByEmail(ctx context.Context, email string) (*repositories.User, error)
	FindByID(ctx context.Context, userID string) (*repositories.User, error)
	UpdateLastLogin(ctx context.Context, userID string) error
	UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error
}

type sessionStore interface {
	Create(ctx context.Context, params repositories.SessionCreateParams) (*repositories.Session, error)
	FindByToken(ctx context.Context, token string) (*repositories.Session, error)
	RevokeByToken(ctx context.Context, token string) error
	Rotate(ctx context.Context, oldToken string, params repositories.SessionCreateParams) (*repositories.Session, error)
}

type AuthMeta struct {
	IP        *string
	UserAgent *string
}

type RegisterInput struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshInput struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutInput struct {
	RefreshToken string `json:"refresh_token"`
}

type ChangePasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type AuthResult struct {
	User         AuthUser `json:"user"`
	UserID       string   `json:"user_id"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
}

type RefreshResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type AuthUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

func NewAuthService(users userStore, sessions sessionStore, tokens *TokenService, accessTokenTTL, refreshTokenTTL, requestTimeout time.Duration) *AuthService {
	return &AuthService{
		users:           users,
		sessions:        sessions,
		tokens:          tokens,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		requestTimeout:  requestTimeout,
	}
}

func (s *AuthService) Register(ctx context.Context, input RegisterInput, meta AuthMeta) (*AuthResult, error) {
	if err := validateRegisterInput(input); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	hash, err := HashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	username := strings.TrimSpace(input.Username)
	if username == "" {
		username = strings.TrimSpace(input.Name)
	}

	user, err := s.users.Create(ctx, normalizeEmail(input.Email), username, hash)
	if err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, user, meta)
}

func (s *AuthService) Login(ctx context.Context, input LoginInput, meta AuthMeta) (*AuthResult, error) {
	if err := validateLoginInput(input); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	user, err := s.users.FindByEmail(ctx, normalizeEmail(input.Email))
	if err != nil {
		if errors.Is(err, repositories.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if !CheckPasswordHash(input.Password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	if err := s.users.UpdateLastLogin(ctx, user.ID); err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, user, meta)
}

func (s *AuthService) Refresh(ctx context.Context, input RefreshInput, meta AuthMeta) (*RefreshResult, error) {
	refreshToken := strings.TrimSpace(input.RefreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("%w: refresh_token is required", ErrInvalidAuthPayload)
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	session, err := s.sessions.FindByToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, repositories.ErrSessionNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	if !session.IsActive || session.ExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidRefreshToken
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, repositories.ErrUserNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	accessToken, err := s.tokens.GenerateToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	newRefreshToken, err := generateOpaqueToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	_, err = s.sessions.Rotate(ctx, refreshToken, repositories.SessionCreateParams{
		UserID:    user.ID,
		Token:     newRefreshToken,
		IP:        meta.IP,
		UserAgent: meta.UserAgent,
		ExpiresAt: time.Now().Add(s.refreshTokenTTL),
	})
	if err != nil {
		if errors.Is(err, repositories.ErrSessionNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, userID string, input LogoutInput) error {
	refreshToken := strings.TrimSpace(input.RefreshToken)
	if refreshToken == "" {
		return fmt.Errorf("%w: refresh_token is required", ErrInvalidAuthPayload)
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	session, err := s.sessions.FindByToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, repositories.ErrSessionNotFound) {
			return ErrInvalidRefreshToken
		}
		return err
	}
	if session.UserID != userID {
		return ErrInvalidRefreshToken
	}

	if err := s.sessions.RevokeByToken(ctx, refreshToken); err != nil {
		if errors.Is(err, repositories.ErrSessionNotFound) {
			return ErrInvalidRefreshToken
		}
		return err
	}
	return nil
}

func (s *AuthService) ChangePassword(ctx context.Context, userID string, input ChangePasswordInput) error {
	switch {
	case strings.TrimSpace(input.CurrentPassword) == "":
		return fmt.Errorf("%w: current_password is required", ErrInvalidAuthPayload)
	case len(input.NewPassword) < 8:
		return fmt.Errorf("%w: new_password must be at least 8 characters", ErrInvalidAuthPayload)
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if !CheckPasswordHash(input.CurrentPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	hash, err := HashPassword(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	return s.users.UpdatePasswordHash(ctx, userID, hash)
}

func (s *AuthService) issueTokens(ctx context.Context, user *repositories.User, meta AuthMeta) (*AuthResult, error) {
	accessToken, err := s.tokens.GenerateToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err := generateOpaqueToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	_, err = s.sessions.Create(ctx, repositories.SessionCreateParams{
		UserID:    user.ID,
		Token:     refreshToken,
		IP:        meta.IP,
		UserAgent: meta.UserAgent,
		ExpiresAt: time.Now().Add(s.refreshTokenTTL),
	})
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		User: AuthUser{
			ID:        user.ID,
			Email:     user.Email,
			Username:  user.Username,
			CreatedAt: user.CreatedAt,
		},
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
	}, nil
}

func validateRegisterInput(input RegisterInput) error {
	input.Email = normalizeEmail(input.Email)
	input.Username = strings.TrimSpace(input.Username)
	if input.Username == "" {
		input.Username = strings.TrimSpace(input.Name)
	}

	switch {
	case input.Email == "":
		return fmt.Errorf("%w: email is required", ErrInvalidAuthPayload)
	case !strings.Contains(input.Email, "@"):
		return fmt.Errorf("%w: email must be valid", ErrInvalidAuthPayload)
	case input.Username == "":
		return fmt.Errorf("%w: username is required", ErrInvalidAuthPayload)
	case len(input.Username) < 3:
		return fmt.Errorf("%w: username must be at least 3 characters", ErrInvalidAuthPayload)
	case len(input.Password) < 8:
		return fmt.Errorf("%w: password must be at least 8 characters", ErrInvalidAuthPayload)
	default:
		return nil
	}
}

func validateLoginInput(input LoginInput) error {
	input.Email = normalizeEmail(input.Email)

	switch {
	case input.Email == "":
		return fmt.Errorf("%w: email is required", ErrInvalidAuthPayload)
	case !strings.Contains(input.Email, "@"):
		return fmt.Errorf("%w: email must be valid", ErrInvalidAuthPayload)
	case input.Password == "":
		return fmt.Errorf("%w: password is required", ErrInvalidAuthPayload)
	default:
		return nil
	}
}

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func generateOpaqueToken() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}
