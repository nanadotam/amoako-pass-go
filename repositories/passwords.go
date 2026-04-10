package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

var ErrPasswordNotFound = errors.New("password entry not found")

type PasswordRecord struct {
	ID                string
	UserID            string
	CategoryID        *string
	Website           string
	Username          *string
	Email             *string
	PasswordEncrypted string
	NotesEncrypted    *string
	URL               *string
	IsFavorite        bool
	PasswordStrength  int
	Tags              []string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type PasswordCreateParams struct {
	UserID            string
	CategoryID        *string
	Website           string
	Username          *string
	Email             *string
	PasswordEncrypted string
	NotesEncrypted    *string
	URL               *string
	IsFavorite        bool
	PasswordStrength  int
	Tags              []string
}

type PasswordUpdateParams struct {
	ID                string
	UserID            string
	CategoryID        *string
	Website           string
	Username          *string
	Email             *string
	PasswordEncrypted string
	NotesEncrypted    *string
	URL               *string
	IsFavorite        bool
	PasswordStrength  int
	Tags              []string
}

type PasswordRepository struct {
	db *sql.DB
}

type PasswordListOptions struct {
	UserID     string
	CategoryID string
	Search     string
}

func NewPasswordRepository(db *sql.DB) *PasswordRepository {
	return &PasswordRepository{db: db}
}

func (r *PasswordRepository) ListByUser(ctx context.Context, options PasswordListOptions) ([]PasswordRecord, error) {
	const query = `
		SELECT id, user_id, category_id, website, username, email, password_encrypted, notes_encrypted, url, is_favorite, password_strength, tags, created_at, updated_at
		FROM passwords
		WHERE user_id = $1
			AND ($2 = '' OR category_id = $2::uuid)
			AND (
				$3 = ''
				OR website ILIKE '%' || $3 || '%'
				OR COALESCE(username, '') ILIKE '%' || $3 || '%'
				OR COALESCE(email, '') ILIKE '%' || $3 || '%'
			)
		ORDER BY updated_at DESC, created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, options.UserID, options.CategoryID, options.Search)
	if err != nil {
		return nil, fmt.Errorf("list passwords by user: %w", err)
	}
	defer rows.Close()

	var records []PasswordRecord
	for rows.Next() {
		var record PasswordRecord
		if err := rows.Scan(
			&record.ID,
			&record.UserID,
			&record.CategoryID,
			&record.Website,
			&record.Username,
			&record.Email,
			&record.PasswordEncrypted,
			&record.NotesEncrypted,
			&record.URL,
			&record.IsFavorite,
			&record.PasswordStrength,
			pq.Array(&record.Tags),
			&record.CreatedAt,
			&record.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan password list row: %w", err)
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate password list rows: %w", err)
	}

	return records, nil
}

func (r *PasswordRepository) FindByID(ctx context.Context, userID, passwordID string) (*PasswordRecord, error) {
	const query = `
		SELECT id, user_id, category_id, website, username, email, password_encrypted, notes_encrypted, url, is_favorite, password_strength, tags, created_at, updated_at
		FROM passwords
		WHERE id = $1 AND user_id = $2
	`

	record := &PasswordRecord{}
	err := r.db.QueryRowContext(ctx, query, passwordID, userID).Scan(
		&record.ID,
		&record.UserID,
		&record.CategoryID,
		&record.Website,
		&record.Username,
		&record.Email,
		&record.PasswordEncrypted,
		&record.NotesEncrypted,
		&record.URL,
		&record.IsFavorite,
		&record.PasswordStrength,
		pq.Array(&record.Tags),
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPasswordNotFound
		}
		return nil, fmt.Errorf("find password by id: %w", err)
	}

	return record, nil
}

func (r *PasswordRepository) Create(ctx context.Context, params PasswordCreateParams) (*PasswordRecord, error) {
	const query = `
		INSERT INTO passwords (
			user_id, category_id, website, username, email, password_encrypted, notes_encrypted, url, is_favorite, password_strength, tags, created_at, updated_at, accessed_at, access_count
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), NOW(), 0)
		RETURNING id, user_id, category_id, website, username, email, password_encrypted, notes_encrypted, url, is_favorite, password_strength, tags, created_at, updated_at
	`

	record := &PasswordRecord{}
	err := r.db.QueryRowContext(ctx, query,
		params.UserID,
		params.CategoryID,
		params.Website,
		params.Username,
		params.Email,
		params.PasswordEncrypted,
		params.NotesEncrypted,
		params.URL,
		params.IsFavorite,
		params.PasswordStrength,
		pq.Array(params.Tags),
	).Scan(
		&record.ID,
		&record.UserID,
		&record.CategoryID,
		&record.Website,
		&record.Username,
		&record.Email,
		&record.PasswordEncrypted,
		&record.NotesEncrypted,
		&record.URL,
		&record.IsFavorite,
		&record.PasswordStrength,
		pq.Array(&record.Tags),
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create password: %w", err)
	}

	return record, nil
}

func (r *PasswordRepository) Update(ctx context.Context, params PasswordUpdateParams) (*PasswordRecord, error) {
	const query = `
		UPDATE passwords
		SET category_id = $3,
			website = $4,
			username = $5,
			email = $6,
			password_encrypted = $7,
			notes_encrypted = $8,
			url = $9,
			is_favorite = $10,
			password_strength = $11,
			tags = $12,
			updated_at = NOW()
		WHERE id = $1 AND user_id = $2
		RETURNING id, user_id, category_id, website, username, email, password_encrypted, notes_encrypted, url, is_favorite, password_strength, tags, created_at, updated_at
	`

	record := &PasswordRecord{}
	err := r.db.QueryRowContext(ctx, query,
		params.ID,
		params.UserID,
		params.CategoryID,
		params.Website,
		params.Username,
		params.Email,
		params.PasswordEncrypted,
		params.NotesEncrypted,
		params.URL,
		params.IsFavorite,
		params.PasswordStrength,
		pq.Array(params.Tags),
	).Scan(
		&record.ID,
		&record.UserID,
		&record.CategoryID,
		&record.Website,
		&record.Username,
		&record.Email,
		&record.PasswordEncrypted,
		&record.NotesEncrypted,
		&record.URL,
		&record.IsFavorite,
		&record.PasswordStrength,
		pq.Array(&record.Tags),
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPasswordNotFound
		}
		return nil, fmt.Errorf("update password: %w", err)
	}

	return record, nil
}

func (r *PasswordRepository) Delete(ctx context.Context, userID, passwordID string) error {
	const query = `DELETE FROM passwords WHERE id = $1 AND user_id = $2`

	result, err := r.db.ExecContext(ctx, query, passwordID, userID)
	if err != nil {
		return fmt.Errorf("delete password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete password rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrPasswordNotFound
	}

	return nil
}
