package services

import (
	"context"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type sessionListStore interface {
	ListByUser(ctx context.Context, userID string) ([]repositories.Session, error)
	RevokeByID(ctx context.Context, userID, sessionID string) error
}

type SessionService struct {
	sessions       sessionListStore
	requestTimeout time.Duration
}

func NewSessionService(sessions sessionListStore, requestTimeout time.Duration) *SessionService {
	return &SessionService{sessions: sessions, requestTimeout: requestTimeout}
}

func (s *SessionService) List(ctx context.Context, userID string) ([]repositories.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.sessions.ListByUser(ctx, userID)
}

func (s *SessionService) Revoke(ctx context.Context, userID, sessionID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.sessions.RevokeByID(ctx, userID, sessionID)
}
