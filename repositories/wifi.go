package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrWifiNotFound = errors.New("wifi entry not found")

type WifiRecord struct {
	ID                string
	UserID            string
	NetworkName       string
	PasswordEncrypted string
	SecurityType      string
	NotesEncrypted    *string
	Location          *string
	IsFavorite        bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type WifiCreateParams struct {
	UserID            string
	NetworkName       string
	PasswordEncrypted string
	SecurityType      string
	NotesEncrypted    *string
	Location          *string
	IsFavorite        bool
}

type WifiUpdateParams struct {
	ID                string
	UserID            string
	NetworkName       string
	PasswordEncrypted string
	SecurityType      string
	NotesEncrypted    *string
	Location          *string
	IsFavorite        bool
}

type WifiRepository struct {
	db *sql.DB
}

func NewWifiRepository(db *sql.DB) *WifiRepository {
	return &WifiRepository{db: db}
}

func (r *WifiRepository) ListByUser(ctx context.Context, userID string) ([]WifiRecord, error) {
	const query = `
		SELECT id, user_id, network_name, password_encrypted, security_type, notes_encrypted, location, is_favorite, created_at, updated_at
		FROM wifi_passwords
		WHERE user_id = $1
		ORDER BY updated_at DESC, created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list wifi: %w", err)
	}
	defer rows.Close()

	var items []WifiRecord
	for rows.Next() {
		var item WifiRecord
		if err := rows.Scan(&item.ID, &item.UserID, &item.NetworkName, &item.PasswordEncrypted, &item.SecurityType, &item.NotesEncrypted, &item.Location, &item.IsFavorite, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan wifi row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate wifi rows: %w", err)
	}
	return items, nil
}

func (r *WifiRepository) FindByID(ctx context.Context, userID, wifiID string) (*WifiRecord, error) {
	const query = `
		SELECT id, user_id, network_name, password_encrypted, security_type, notes_encrypted, location, is_favorite, created_at, updated_at
		FROM wifi_passwords
		WHERE id = $1 AND user_id = $2
	`
	item := &WifiRecord{}
	err := r.db.QueryRowContext(ctx, query, wifiID, userID).Scan(
		&item.ID, &item.UserID, &item.NetworkName, &item.PasswordEncrypted, &item.SecurityType, &item.NotesEncrypted, &item.Location, &item.IsFavorite, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrWifiNotFound
		}
		return nil, fmt.Errorf("find wifi by id: %w", err)
	}
	return item, nil
}

func (r *WifiRepository) Create(ctx context.Context, params WifiCreateParams) (*WifiRecord, error) {
	const query = `
		INSERT INTO wifi_passwords (user_id, network_name, password_encrypted, security_type, notes_encrypted, location, is_favorite, created_at, updated_at, accessed_at, access_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), NOW(), 0)
		RETURNING id, user_id, network_name, password_encrypted, security_type, notes_encrypted, location, is_favorite, created_at, updated_at
	`
	item := &WifiRecord{}
	err := r.db.QueryRowContext(ctx, query, params.UserID, params.NetworkName, params.PasswordEncrypted, params.SecurityType, params.NotesEncrypted, params.Location, params.IsFavorite).Scan(
		&item.ID, &item.UserID, &item.NetworkName, &item.PasswordEncrypted, &item.SecurityType, &item.NotesEncrypted, &item.Location, &item.IsFavorite, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create wifi: %w", err)
	}
	return item, nil
}

func (r *WifiRepository) Update(ctx context.Context, params WifiUpdateParams) (*WifiRecord, error) {
	const query = `
		UPDATE wifi_passwords
		SET network_name = $3,
			password_encrypted = $4,
			security_type = $5,
			notes_encrypted = $6,
			location = $7,
			is_favorite = $8,
			updated_at = NOW()
		WHERE id = $1 AND user_id = $2
		RETURNING id, user_id, network_name, password_encrypted, security_type, notes_encrypted, location, is_favorite, created_at, updated_at
	`
	item := &WifiRecord{}
	err := r.db.QueryRowContext(ctx, query, params.ID, params.UserID, params.NetworkName, params.PasswordEncrypted, params.SecurityType, params.NotesEncrypted, params.Location, params.IsFavorite).Scan(
		&item.ID, &item.UserID, &item.NetworkName, &item.PasswordEncrypted, &item.SecurityType, &item.NotesEncrypted, &item.Location, &item.IsFavorite, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrWifiNotFound
		}
		return nil, fmt.Errorf("update wifi: %w", err)
	}
	return item, nil
}

func (r *WifiRepository) Delete(ctx context.Context, userID, wifiID string) error {
	const query = `DELETE FROM wifi_passwords WHERE id = $1 AND user_id = $2`
	result, err := r.db.ExecContext(ctx, query, wifiID, userID)
	if err != nil {
		return fmt.Errorf("delete wifi: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete wifi rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrWifiNotFound
	}
	return nil
}
