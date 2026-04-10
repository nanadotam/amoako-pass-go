package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type categoryStore interface {
	ListByUser(ctx context.Context, userID string) ([]repositories.Category, error)
	Create(ctx context.Context, params repositories.CategoryParams) (*repositories.Category, error)
	Update(ctx context.Context, params repositories.CategoryUpdateParams) (*repositories.Category, error)
	Delete(ctx context.Context, userID, categoryID string) error
}

type CategoryService struct {
	categories     categoryStore
	requestTimeout time.Duration
}

type CategoryInput struct {
	Name  string  `json:"name"`
	Color *string `json:"color"`
	Icon  *string `json:"icon"`
}

func NewCategoryService(categories categoryStore, requestTimeout time.Duration) *CategoryService {
	return &CategoryService{categories: categories, requestTimeout: requestTimeout}
}

func (s *CategoryService) List(ctx context.Context, userID string) ([]repositories.Category, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.categories.ListByUser(ctx, userID)
}

func (s *CategoryService) Create(ctx context.Context, userID string, input CategoryInput) (*repositories.Category, error) {
	clean, err := normalizeCategoryInput(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.categories.Create(ctx, repositories.CategoryParams{
		UserID: userID,
		Name:   clean.Name,
		Color:  clean.Color,
		Icon:   clean.Icon,
	})
}

func (s *CategoryService) Update(ctx context.Context, userID, categoryID string, input CategoryInput) (*repositories.Category, error) {
	clean, err := normalizeCategoryInput(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.categories.Update(ctx, repositories.CategoryUpdateParams{
		ID:     categoryID,
		UserID: userID,
		Name:   clean.Name,
		Color:  clean.Color,
		Icon:   clean.Icon,
	})
}

func (s *CategoryService) Delete(ctx context.Context, userID, categoryID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.categories.Delete(ctx, userID, categoryID)
}

func normalizeCategoryInput(input CategoryInput) (CategoryInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return CategoryInput{}, fmt.Errorf("%w: category name is required", ErrInvalidVaultPayload)
	}
	input.Color = trimPointer(input.Color)
	input.Icon = trimPointer(input.Icon)
	return input, nil
}
