package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type AuditLog struct {
	ID           string          `json:"id"`
	Action       string          `json:"action"`
	ResourceType *string         `json:"resource_type,omitempty"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	IP           *string         `json:"ip,omitempty"`
	UserAgent    *string         `json:"device,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

type AuditLogCreateParams struct {
	UserID       string
	Action       string
	ResourceType *string
	ResourceID   *string
	IP           *string
	UserAgent    *string
	Details      []byte
}

type AuditLogListOptions struct {
	UserID  string
	Action  string
	Page    int
	PerPage int
}

type AuditLogRepository struct {
	db *sql.DB
}

func NewAuditLogRepository(db *sql.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) Create(ctx context.Context, params AuditLogCreateParams) error {
	const query = `
		INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	`
	if _, err := r.db.ExecContext(ctx, query, params.UserID, params.Action, params.ResourceType, params.ResourceID, params.IP, params.UserAgent, params.Details); err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}
	return nil
}

func (r *AuditLogRepository) ListByUser(ctx context.Context, options AuditLogListOptions) ([]AuditLog, error) {
	offset := (options.Page - 1) * options.PerPage
	const query = `
		SELECT id, action, resource_type, resource_id::text, ip_address::text, user_agent, COALESCE(details, '{}'::jsonb)::text, created_at
		FROM audit_logs
		WHERE user_id = $1
			AND ($2 = '' OR action = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := r.db.QueryContext(ctx, query, options.UserID, options.Action, options.PerPage, offset)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var items []AuditLog
	for rows.Next() {
		var item AuditLog
		var details string
		if err := rows.Scan(&item.ID, &item.Action, &item.ResourceType, &item.ResourceID, &item.IP, &item.UserAgent, &details, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit log row: %w", err)
		}
		item.Details = json.RawMessage(details)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit logs: %w", err)
	}
	return items, nil
}
