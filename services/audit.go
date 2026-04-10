package services

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type auditStore interface {
	Create(ctx context.Context, params repositories.AuditLogCreateParams) error
	ListByUser(ctx context.Context, options repositories.AuditLogListOptions) ([]repositories.AuditLog, error)
}

type AuditService struct {
	logs           auditStore
	requestTimeout time.Duration
}

type AuditEntry struct {
	UserID       string
	Action       string
	ResourceType string
	ResourceID   string
	IP           *string
	UserAgent    *string
	Details      map[string]any
}

func NewAuditService(logs auditStore, requestTimeout time.Duration) *AuditService {
	return &AuditService{logs: logs, requestTimeout: requestTimeout}
}

func (s *AuditService) Write(ctx context.Context, entry AuditEntry) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	var details []byte
	if entry.Details != nil {
		details, _ = json.Marshal(entry.Details)
	}

	var resourceType *string
	if trimmed := strings.TrimSpace(entry.ResourceType); trimmed != "" {
		resourceType = &trimmed
	}
	var resourceID *string
	if trimmed := strings.TrimSpace(entry.ResourceID); trimmed != "" {
		resourceID = &trimmed
	}

	return s.logs.Create(ctx, repositories.AuditLogCreateParams{
		UserID:       entry.UserID,
		Action:       entry.Action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IP:           entry.IP,
		UserAgent:    entry.UserAgent,
		Details:      details,
	})
}

func (s *AuditService) List(ctx context.Context, userID, action string, page, perPage int) ([]repositories.AuditLog, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.logs.ListByUser(ctx, repositories.AuditLogListOptions{
		UserID:  userID,
		Action:  strings.TrimSpace(action),
		Page:    page,
		PerPage: perPage,
	})
}
