package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrCategoryNotFound = errors.New("category not found")

type Category struct {
	ID        string
	UserID    string
	Name      string
	Color     *string
	Icon      *string
	IsDefault bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type CategoryParams struct {
	UserID string
	Name   string
	Color  *string
	Icon   *string
}

type CategoryUpdateParams struct {
	ID     string
	UserID string
	Name   string
	Color  *string
	Icon   *string
}

type CategoryRepository struct {
	db *sql.DB
}

func NewCategoryRepository(db *sql.DB) *CategoryRepository {
	return &CategoryRepository{db: db}
}

func (r *CategoryRepository) ListByUser(ctx context.Context, userID string) ([]Category, error) {
	const query = `
		SELECT id, user_id, name, color, icon, is_default, created_at, updated_at
		FROM categories
		WHERE user_id = $1
		ORDER BY is_default DESC, sort_order ASC, name ASC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list categories: %w", err)
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		var category Category
		if err := rows.Scan(&category.ID, &category.UserID, &category.Name, &category.Color, &category.Icon, &category.IsDefault, &category.CreatedAt, &category.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan category row: %w", err)
		}
		categories = append(categories, category)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate categories: %w", err)
	}
	return categories, nil
}

func (r *CategoryRepository) Create(ctx context.Context, params CategoryParams) (*Category, error) {
	const query = `
		INSERT INTO categories (user_id, name, color, icon, is_default, created_at, updated_at)
		VALUES ($1, $2, $3, $4, FALSE, NOW(), NOW())
		RETURNING id, user_id, name, color, icon, is_default, created_at, updated_at
	`
	category := &Category{}
	err := r.db.QueryRowContext(ctx, query, params.UserID, params.Name, params.Color, params.Icon).Scan(
		&category.ID, &category.UserID, &category.Name, &category.Color, &category.Icon, &category.IsDefault, &category.CreatedAt, &category.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUserConflict
		}
		return nil, fmt.Errorf("create category: %w", err)
	}
	return category, nil
}

func (r *CategoryRepository) Update(ctx context.Context, params CategoryUpdateParams) (*Category, error) {
	const query = `
		UPDATE categories
		SET name = $3, color = $4, icon = $5, updated_at = NOW()
		WHERE id = $1 AND user_id = $2
		RETURNING id, user_id, name, color, icon, is_default, created_at, updated_at
	`
	category := &Category{}
	err := r.db.QueryRowContext(ctx, query, params.ID, params.UserID, params.Name, params.Color, params.Icon).Scan(
		&category.ID, &category.UserID, &category.Name, &category.Color, &category.Icon, &category.IsDefault, &category.CreatedAt, &category.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCategoryNotFound
		}
		return nil, fmt.Errorf("update category: %w", err)
	}
	return category, nil
}

func (r *CategoryRepository) Delete(ctx context.Context, userID, categoryID string) error {
	const query = `DELETE FROM categories WHERE id = $1 AND user_id = $2 AND is_default = FALSE`
	result, err := r.db.ExecContext(ctx, query, categoryID, userID)
	if err != nil {
		return fmt.Errorf("delete category: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete category rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrCategoryNotFound
	}
	return nil
}
