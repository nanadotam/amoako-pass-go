package services

import (
	"context"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type userProfileStore interface {
	Profile(ctx context.Context, userID string) (*repositories.UserProfile, error)
}

type UserService struct {
	users          userProfileStore
	requestTimeout time.Duration
}

func NewUserService(users userProfileStore, requestTimeout time.Duration) *UserService {
	return &UserService{users: users, requestTimeout: requestTimeout}
}

func (s *UserService) Profile(ctx context.Context, userID string) (*repositories.UserProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.users.Profile(ctx, userID)
}
