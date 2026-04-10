package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type Session struct {
	ID           string
	UserID       string
	Token        string
	IP           *string
	UserAgent    *string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	LastAccessed time.Time
	IsActive     bool
}

type SessionCreateParams struct {
	UserID    string
	Token     string
	IP        *string
	UserAgent *string
	ExpiresAt time.Time
}

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, params SessionCreateParams) (*Session, error) {
	const query = `
		INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at, created_at, last_accessed, is_active)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), TRUE)
		RETURNING id, user_id, session_token, ip_address::text, user_agent, expires_at, created_at, last_accessed, is_active
	`

	session := &Session{}
	err := r.db.QueryRowContext(ctx, query, params.UserID, params.Token, params.IP, params.UserAgent, params.ExpiresAt).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.IP,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.LastAccessed,
		&session.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return session, nil
}

func (r *SessionRepository) FindByToken(ctx context.Context, token string) (*Session, error) {
	const query = `
		SELECT id, user_id, session_token, ip_address::text, user_agent, expires_at, created_at, last_accessed, is_active
		FROM user_sessions
		WHERE session_token = $1
	`

	session := &Session{}
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.IP,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.LastAccessed,
		&session.IsActive,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("find session by token: %w", err)
	}

	return session, nil
}

func (r *SessionRepository) RevokeByToken(ctx context.Context, token string) error {
	const query = `UPDATE user_sessions SET is_active = FALSE, last_accessed = NOW() WHERE session_token = $1 AND is_active = TRUE`

	result, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("revoke session by token: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke session rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrSessionNotFound
	}
	return nil
}

func (r *SessionRepository) Rotate(ctx context.Context, oldToken string, params SessionCreateParams) (*Session, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin session rotation tx: %w", err)
	}
	defer tx.Rollback()

	const revokeQuery = `UPDATE user_sessions SET is_active = FALSE, last_accessed = NOW() WHERE session_token = $1 AND is_active = TRUE`
	result, err := tx.ExecContext(ctx, revokeQuery, oldToken)
	if err != nil {
		return nil, fmt.Errorf("revoke session for rotation: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("rotation rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return nil, ErrSessionNotFound
	}

	const createQuery = `
		INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at, created_at, last_accessed, is_active)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), TRUE)
		RETURNING id, user_id, session_token, ip_address::text, user_agent, expires_at, created_at, last_accessed, is_active
	`
	session := &Session{}
	err = tx.QueryRowContext(ctx, createQuery, params.UserID, params.Token, params.IP, params.UserAgent, params.ExpiresAt).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.IP,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.LastAccessed,
		&session.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("create rotated session: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit session rotation tx: %w", err)
	}
	return session, nil
}

func (r *SessionRepository) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	const query = `
		SELECT id, user_id, session_token, ip_address::text, user_agent, expires_at, created_at, last_accessed, is_active
		FROM user_sessions
		WHERE user_id = $1 AND is_active = TRUE
		ORDER BY last_accessed DESC, created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.ID, &session.UserID, &session.Token, &session.IP, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt, &session.LastAccessed, &session.IsActive); err != nil {
			return nil, fmt.Errorf("scan session row: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

func (r *SessionRepository) RevokeByID(ctx context.Context, userID, sessionID string) error {
	const query = `UPDATE user_sessions SET is_active = FALSE, last_accessed = NOW() WHERE id = $1 AND user_id = $2 AND is_active = TRUE`
	result, err := r.db.ExecContext(ctx, query, sessionID, userID)
	if err != nil {
		return fmt.Errorf("revoke session by id: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke session by id rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrSessionNotFound
	}
	return nil
}
