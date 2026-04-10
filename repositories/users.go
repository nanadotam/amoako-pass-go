package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrUserConflict = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID           string
	Email        string
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

type UserProfile struct {
	ID            string
	Name          string
	Email         string
	PasswordCount int
	WifiCount     int
	CategoryCount int
	SecurityScore int
	MemberSince   time.Time
}

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, email, username, passwordHash string) (*User, error) {
	const query = `
		INSERT INTO users (email, username, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING id, email, username, password_hash, created_at
	`

	user := &User{}
	err := r.db.QueryRowContext(ctx, query, email, username, passwordHash).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUserConflict
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	return user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*User, error) {
	const query = `
		SELECT id, email, username, password_hash, created_at
		FROM users
		WHERE email = $1
	`

	user := &User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	return user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, userID string) (*User, error) {
	const query = `
		SELECT id, email, username, password_hash, created_at
		FROM users
		WHERE id = $1
	`

	user := &User{}
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user by id: %w", err)
	}

	return user, nil
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	const query = `UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = $1`

	if _, err := r.db.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("update last login: %w", err)
	}

	return nil
}

func (r *UserRepository) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	const query = `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update password hash rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) Profile(ctx context.Context, userID string) (*UserProfile, error) {
	const query = `
		SELECT
			u.id,
			u.username,
			u.email,
			COALESCE((SELECT COUNT(*) FROM passwords p WHERE p.user_id = u.id), 0),
			COALESCE((SELECT COUNT(*) FROM wifi_passwords w WHERE w.user_id = u.id), 0),
			COALESCE((SELECT COUNT(*) FROM categories c WHERE c.user_id = u.id), 0),
			COALESCE((SELECT AVG(p.password_strength)::int FROM passwords p WHERE p.user_id = u.id), 0),
			u.created_at
		FROM users u
		WHERE u.id = $1
	`

	profile := &UserProfile{}
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&profile.ID,
		&profile.Name,
		&profile.Email,
		&profile.PasswordCount,
		&profile.WifiCount,
		&profile.CategoryCount,
		&profile.SecurityScore,
		&profile.MemberSince,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("load user profile: %w", err)
	}

	return profile, nil
}
