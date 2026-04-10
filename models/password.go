package models

import (
	"github.com/google/uuid"
	"time"
)

type Password struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	UserID             uuid.UUID  `json:"user_id" db:"user_id"`
	CategoryID         *uuid.UUID `json:"category_id" db:"category_id"`
	Website            string     `json:"website" db:"website"`
	Username           *string    `json:"username" db:"username"`
	Email              *string    `json:"email" db:"email"`
	PasswordEncrypted  string     `json:"password_encrypted" db:"password_encrypted"`
	NotesEncrypted     *string    `json:"notes_encrypted" db:"notes_encrypted"`
	FaviconURL         *string    `json:"favicon_url" db:"favicon_url"`
	URL                *string    `json:"url" db:"url"`
	IsFavorite         bool       `json:"is_favorite" db:"is_favorite"`
	PasswordStrength   int        `json:"password_strength" db:"password_strength"`
	LastPasswordChange time.Time  `json:"last_password_change" db:"last_password_change"`
	PasswordHistory    []string   `json:"password_history" db:"password_history"`
	Tags               []string   `json:"tags" db:"tags"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
	AccessedAt         time.Time  `json:"accessed_at" db:"accessed_at"`
	AccessCount        int        `json:"access_count" db:"access_count"`
}

type PasswordCreation struct {
	Website    string     `json:"website"`
	Username   *string    `json:"username"`
	Email      *string    `json:"email"`
	Password   string     `json:"password"`
	Notes      *string    `json:"notes"`
	CategoryID *uuid.UUID `json:"category_id"`
	Tags       []string   `json:"tags"`
}
