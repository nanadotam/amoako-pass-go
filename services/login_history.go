package services

import (
	"context"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type loginHistoryReader interface {
	ListByUser(ctx context.Context, userID string, limit int) ([]repositories.LoginHistoryRecord, error)
	SetTrusted(ctx context.Context, userID, id string, trusted bool) error
	Delete(ctx context.Context, userID, id string) error
	ClearByUser(ctx context.Context, userID string) error
}

type LoginHistoryService struct {
	repo           loginHistoryReader
	requestTimeout time.Duration
}

func NewLoginHistoryService(repo loginHistoryReader, requestTimeout time.Duration) *LoginHistoryService {
	return &LoginHistoryService{repo: repo, requestTimeout: requestTimeout}
}

func (s *LoginHistoryService) List(ctx context.Context, userID string, limit int) ([]repositories.LoginHistoryRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.repo.ListByUser(ctx, userID, limit)
}

func (s *LoginHistoryService) SetTrusted(ctx context.Context, userID, id string, trusted bool) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.repo.SetTrusted(ctx, userID, id, trusted)
}

func (s *LoginHistoryService) Delete(ctx context.Context, userID, id string) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.repo.Delete(ctx, userID, id)
}

func (s *LoginHistoryService) ClearAll(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.repo.ClearByUser(ctx, userID)
}
