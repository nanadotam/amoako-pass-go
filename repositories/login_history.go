package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrLoginHistoryNotFound = errors.New("login history not found")

type LoginHistoryRecord struct {
	ID        string
	UserID    string
	LoggedAt  time.Time
	Latitude  *float64
	Longitude *float64
	City      *string
	Country   *string
	IsTrusted bool
	IP        *string
	UserAgent *string
}

type LoginHistoryCreateParams struct {
	UserID    string
	Latitude  *float64
	Longitude *float64
	City      *string
	Country   *string
	IP        *string
	UserAgent *string
}

type LoginHistoryRepository struct {
	db *sql.DB
}

func NewLoginHistoryRepository(db *sql.DB) *LoginHistoryRepository {
	return &LoginHistoryRepository{db: db}
}

func (r *LoginHistoryRepository) Create(ctx context.Context, params LoginHistoryCreateParams) (*LoginHistoryRecord, error) {
	const query = `
		INSERT INTO login_history (user_id, latitude, longitude, city, country, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, logged_at, latitude, longitude, city, country, is_trusted, ip_address, user_agent
	`
	record := &LoginHistoryRecord{}
	err := r.db.QueryRowContext(ctx, query,
		params.UserID, params.Latitude, params.Longitude,
		params.City, params.Country, params.IP, params.UserAgent,
	).Scan(
		&record.ID, &record.UserID, &record.LoggedAt,
		&record.Latitude, &record.Longitude,
		&record.City, &record.Country,
		&record.IsTrusted, &record.IP, &record.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("create login history: %w", err)
	}
	return record, nil
}

func (r *LoginHistoryRepository) ListByUser(ctx context.Context, userID string, limit int) ([]LoginHistoryRecord, error) {
	const query = `
		SELECT id, user_id, logged_at, latitude, longitude, city, country, is_trusted, ip_address, user_agent
		FROM login_history
		WHERE user_id = $1
		ORDER BY logged_at DESC
		LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list login history: %w", err)
	}
	defer rows.Close()

	var items []LoginHistoryRecord
	for rows.Next() {
		var rec LoginHistoryRecord
		if err := rows.Scan(
			&rec.ID, &rec.UserID, &rec.LoggedAt,
			&rec.Latitude, &rec.Longitude,
			&rec.City, &rec.Country,
			&rec.IsTrusted, &rec.IP, &rec.UserAgent,
		); err != nil {
			return nil, fmt.Errorf("scan login history: %w", err)
		}
		items = append(items, rec)
	}
	return items, rows.Err()
}

func (r *LoginHistoryRepository) SetTrusted(ctx context.Context, userID, id string, trusted bool) error {
	const query = `UPDATE login_history SET is_trusted = $3 WHERE id = $1 AND user_id = $2`
	result, err := r.db.ExecContext(ctx, query, id, userID, trusted)
	if err != nil {
		return fmt.Errorf("set trusted: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrLoginHistoryNotFound
	}
	return nil
}

func (r *LoginHistoryRepository) Delete(ctx context.Context, userID, id string) error {
	const query = `DELETE FROM login_history WHERE id = $1 AND user_id = $2`
	result, err := r.db.ExecContext(ctx, query, id, userID)
	if err != nil {
		return fmt.Errorf("delete login history: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrLoginHistoryNotFound
	}
	return nil
}

func (r *LoginHistoryRepository) ClearByUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM login_history WHERE user_id = $1`, userID)
	return err
}
