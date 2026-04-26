package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

var ErrInvalidVaultPayload = errors.New("invalid vault payload")

type passwordStore interface {
	ListByUser(ctx context.Context, options repositories.PasswordListOptions) ([]repositories.PasswordRecord, error)
	FindByID(ctx context.Context, userID, passwordID string) (*repositories.PasswordRecord, error)
	Create(ctx context.Context, params repositories.PasswordCreateParams) (*repositories.PasswordRecord, error)
	Update(ctx context.Context, params repositories.PasswordUpdateParams) (*repositories.PasswordRecord, error)
	Delete(ctx context.Context, userID, passwordID string) error
}

type VaultService struct {
	passwords      passwordStore
	categories     categoryStore
	encryption     *EncryptionService
	requestTimeout time.Duration
}

type PasswordInput struct {
	CategoryID *string  `json:"category_id"`
	Website    string   `json:"website"`
	Username   *string  `json:"username"`
	Email      *string  `json:"email"`
	Password   string   `json:"password"`
	Notes      *string  `json:"notes"`
	URL        *string  `json:"url"`
	IsFavorite bool     `json:"is_favorite"`
	Tags       []string `json:"tags"`
}

type PasswordListQuery struct {
	CategoryID string
	Search     string
}

type PasswordListItem struct {
	ID               string    `json:"id"`
	CategoryID       *string   `json:"category_id,omitempty"`
	Website          string    `json:"website"`
	Username         *string   `json:"username,omitempty"`
	Email            *string   `json:"email,omitempty"`
	URL              *string   `json:"url,omitempty"`
	IsFavorite       bool      `json:"is_favorite"`
	Tags             []string  `json:"tags"`
	PasswordStrength int       `json:"password_strength"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type PasswordDetail struct {
	ID               string    `json:"id"`
	CategoryID       *string   `json:"category_id,omitempty"`
	Website          string    `json:"website"`
	Username         *string   `json:"username,omitempty"`
	Email            *string   `json:"email,omitempty"`
	Password         string    `json:"password"`
	Notes            *string   `json:"notes,omitempty"`
	URL              *string   `json:"url,omitempty"`
	IsFavorite       bool      `json:"is_favorite"`
	Tags             []string  `json:"tags"`
	PasswordStrength int       `json:"password_strength"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type FlutterPasswordInput struct {
	ID                string     `json:"id,omitempty"`
	Name              string     `json:"name"`
	Username          string     `json:"username"`
	EncryptedPassword string     `json:"encryptedPassword"`
	URL               string     `json:"url"`
	Notes             string     `json:"notes"`
	Category          string     `json:"category"`
	StrengthScore     int        `json:"strengthScore"`
	CreatedAt         *time.Time `json:"createdAt,omitempty"`
	UpdatedAt         *time.Time `json:"updatedAt,omitempty"`
}

type FlutterPasswordListItem struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Username          string    `json:"username"`
	EncryptedPassword string    `json:"encryptedPassword"`
	URL               string    `json:"url"`
	Notes             string    `json:"notes"`
	Category          string    `json:"category"`
	StrengthScore     int       `json:"strengthScore"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type FlutterPasswordDetail struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Username          string    `json:"username"`
	EncryptedPassword string    `json:"encryptedPassword"`
	URL               string    `json:"url"`
	Notes             string    `json:"notes"`
	Category          string    `json:"category"`
	StrengthScore     int       `json:"strengthScore"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func NewVaultService(passwords passwordStore, categories categoryStore, encryption *EncryptionService, requestTimeout time.Duration) *VaultService {
	return &VaultService{
		passwords:      passwords,
		categories:     categories,
		encryption:     encryption,
		requestTimeout: requestTimeout,
	}
}

func (s *VaultService) List(ctx context.Context, userID string, query PasswordListQuery) ([]PasswordListItem, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	records, err := s.passwords.ListByUser(ctx, repositories.PasswordListOptions{
		UserID:     userID,
		CategoryID: strings.TrimSpace(query.CategoryID),
		Search:     strings.TrimSpace(query.Search),
	})
	if err != nil {
		return nil, err
	}

	items := make([]PasswordListItem, 0, len(records))
	for _, record := range records {
		items = append(items, PasswordListItem{
			ID:               record.ID,
			CategoryID:       record.CategoryID,
			Website:          record.Website,
			Username:         record.Username,
			Email:            record.Email,
			URL:              record.URL,
			IsFavorite:       record.IsFavorite,
			Tags:             record.Tags,
			PasswordStrength: record.PasswordStrength,
			CreatedAt:        record.CreatedAt,
			UpdatedAt:        record.UpdatedAt,
		})
	}

	return items, nil
}

func (s *VaultService) Get(ctx context.Context, userID, passwordID string) (*PasswordDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.passwords.FindByID(ctx, userID, passwordID)
	if err != nil {
		return nil, err
	}

	password, err := s.encryption.Decrypt(record.PasswordEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt password: %w", err)
	}

	var notes *string
	if record.NotesEncrypted != nil {
		decryptedNotes, err := s.encryption.Decrypt(*record.NotesEncrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt notes: %w", err)
		}
		notes = &decryptedNotes
	}

	return &PasswordDetail{
		ID:               record.ID,
		CategoryID:       record.CategoryID,
		Website:          record.Website,
		Username:         record.Username,
		Email:            record.Email,
		Password:         password,
		Notes:            notes,
		URL:              record.URL,
		IsFavorite:       record.IsFavorite,
		Tags:             record.Tags,
		PasswordStrength: record.PasswordStrength,
		CreatedAt:        record.CreatedAt,
		UpdatedAt:        record.UpdatedAt,
	}, nil
}

func (s *VaultService) Create(ctx context.Context, userID string, input PasswordInput) (*PasswordDetail, error) {
	params, err := s.prepareCreateParams(userID, input)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.passwords.Create(ctx, params)
	if err != nil {
		return nil, err
	}

	return s.toDetail(record)
}

func (s *VaultService) Update(ctx context.Context, userID, passwordID string, input PasswordInput) (*PasswordDetail, error) {
	params, err := s.prepareUpdateParams(userID, passwordID, input)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.passwords.Update(ctx, params)
	if err != nil {
		return nil, err
	}

	return s.toDetail(record)
}

func (s *VaultService) Delete(ctx context.Context, userID, passwordID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	return s.passwords.Delete(ctx, userID, passwordID)
}

func (s *VaultService) FlutterList(ctx context.Context, userID string) ([]FlutterPasswordListItem, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	records, err := s.passwords.ListByUser(ctx, repositories.PasswordListOptions{UserID: userID})
	if err != nil {
		return nil, err
	}
	categoryNames, err := s.categoryNamesByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	items := make([]FlutterPasswordListItem, 0, len(records))
	for _, record := range records {
		items = append(items, toFlutterPasswordListItem(record, categoryNames))
	}

	return items, nil
}

func (s *VaultService) FlutterGet(ctx context.Context, userID, passwordID string) (*FlutterPasswordDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.passwords.FindByID(ctx, userID, passwordID)
	if err != nil {
		return nil, err
	}
	categoryNames, err := s.categoryNamesByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	item := toFlutterPasswordDetail(*record, categoryNames)
	return &item, nil
}

func (s *VaultService) FlutterCreate(ctx context.Context, userID string, input FlutterPasswordInput) (*FlutterPasswordDetail, error) {
	params, err := prepareFlutterPasswordCreateParams(userID, input)
	if err != nil {
		return nil, err
	}
	categoryID, err := s.resolveFlutterCategoryID(ctx, userID, input.Category)
	if err == nil {
		params.CategoryID = categoryID
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.passwords.Create(ctx, params)
	if err != nil {
		return nil, err
	}
	categoryNames, err := s.categoryNamesByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	item := toFlutterPasswordDetail(*record, categoryNames)
	return &item, nil
}

func (s *VaultService) FlutterUpdate(ctx context.Context, userID, passwordID string, input FlutterPasswordInput) (*FlutterPasswordDetail, error) {
	params, err := prepareFlutterPasswordUpdateParams(userID, passwordID, input)
	if err != nil {
		return nil, err
	}
	categoryID, err := s.resolveFlutterCategoryID(ctx, userID, input.Category)
	if err == nil {
		params.CategoryID = categoryID
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.passwords.Update(ctx, params)
	if err != nil {
		return nil, err
	}
	categoryNames, err := s.categoryNamesByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	item := toFlutterPasswordDetail(*record, categoryNames)
	return &item, nil
}

func (s *VaultService) prepareCreateParams(userID string, input PasswordInput) (repositories.PasswordCreateParams, error) {
	clean, err := normalizePasswordInput(input)
	if err != nil {
		return repositories.PasswordCreateParams{}, err
	}

	passwordEncrypted, err := s.encryption.Encrypt(clean.Password)
	if err != nil {
		return repositories.PasswordCreateParams{}, fmt.Errorf("encrypt password: %w", err)
	}

	var notesEncrypted *string
	if clean.Notes != nil {
		encryptedNotes, err := s.encryption.Encrypt(*clean.Notes)
		if err != nil {
			return repositories.PasswordCreateParams{}, fmt.Errorf("encrypt notes: %w", err)
		}
		notesEncrypted = &encryptedNotes
	}

	return repositories.PasswordCreateParams{
		UserID:            userID,
		CategoryID:        clean.CategoryID,
		Website:           clean.Website,
		Username:          clean.Username,
		Email:             clean.Email,
		PasswordEncrypted: passwordEncrypted,
		NotesEncrypted:    notesEncrypted,
		URL:               clean.URL,
		IsFavorite:        clean.IsFavorite,
		PasswordStrength:  scorePassword(clean.Password),
		Tags:              clean.Tags,
	}, nil
}

func (s *VaultService) prepareUpdateParams(userID, passwordID string, input PasswordInput) (repositories.PasswordUpdateParams, error) {
	clean, err := normalizePasswordInput(input)
	if err != nil {
		return repositories.PasswordUpdateParams{}, err
	}

	passwordEncrypted, err := s.encryption.Encrypt(clean.Password)
	if err != nil {
		return repositories.PasswordUpdateParams{}, fmt.Errorf("encrypt password: %w", err)
	}

	var notesEncrypted *string
	if clean.Notes != nil {
		encryptedNotes, err := s.encryption.Encrypt(*clean.Notes)
		if err != nil {
			return repositories.PasswordUpdateParams{}, fmt.Errorf("encrypt notes: %w", err)
		}
		notesEncrypted = &encryptedNotes
	}

	return repositories.PasswordUpdateParams{
		ID:                passwordID,
		UserID:            userID,
		CategoryID:        clean.CategoryID,
		Website:           clean.Website,
		Username:          clean.Username,
		Email:             clean.Email,
		PasswordEncrypted: passwordEncrypted,
		NotesEncrypted:    notesEncrypted,
		URL:               clean.URL,
		IsFavorite:        clean.IsFavorite,
		PasswordStrength:  scorePassword(clean.Password),
		Tags:              clean.Tags,
	}, nil
}

func (s *VaultService) toDetail(record *repositories.PasswordRecord) (*PasswordDetail, error) {
	password, err := s.encryption.Decrypt(record.PasswordEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt password: %w", err)
	}

	var notes *string
	if record.NotesEncrypted != nil {
		decryptedNotes, err := s.encryption.Decrypt(*record.NotesEncrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt notes: %w", err)
		}
		notes = &decryptedNotes
	}

	return &PasswordDetail{
		ID:               record.ID,
		CategoryID:       record.CategoryID,
		Website:          record.Website,
		Username:         record.Username,
		Email:            record.Email,
		Password:         password,
		Notes:            notes,
		URL:              record.URL,
		IsFavorite:       record.IsFavorite,
		Tags:             record.Tags,
		PasswordStrength: record.PasswordStrength,
		CreatedAt:        record.CreatedAt,
		UpdatedAt:        record.UpdatedAt,
	}, nil
}

func normalizePasswordInput(input PasswordInput) (PasswordInput, error) {
	input.Website = strings.TrimSpace(input.Website)

	if input.Website == "" {
		return PasswordInput{}, fmt.Errorf("%w: website is required", ErrInvalidVaultPayload)
	}
	if strings.TrimSpace(input.Password) == "" {
		return PasswordInput{}, fmt.Errorf("%w: password is required", ErrInvalidVaultPayload)
	}

	input.Username = trimPointer(input.Username)
	input.Email = trimPointer(input.Email)
	input.URL = trimPointer(input.URL)
	input.Notes = trimPointer(input.Notes)
	input.CategoryID = trimPointer(input.CategoryID)
	input.Tags = normalizeTags(input.Tags)

	return input, nil
}

func trimPointer(value *string) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}

func normalizeTags(tags []string) []string {
	seen := make(map[string]struct{}, len(tags))
	clean := make([]string, 0, len(tags))

	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		clean = append(clean, trimmed)
	}

	return clean
}

func scorePassword(password string) int {
	score := 0
	if len(password) >= 8 {
		score += 20
	}
	if len(password) >= 12 {
		score += 20
	}
	if strings.IndexFunc(password, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0 {
		score += 15
	}
	if strings.IndexFunc(password, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0 {
		score += 15
	}
	if strings.IndexFunc(password, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
		score += 15
	}
	if strings.IndexFunc(password, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) >= 0 {
		score += 15
	}
	if score > 100 {
		score = 100
	}
	return score
}

func prepareFlutterPasswordCreateParams(userID string, input FlutterPasswordInput) (repositories.PasswordCreateParams, error) {
	clean, err := normalizeFlutterPasswordInput(input)
	if err != nil {
		return repositories.PasswordCreateParams{}, err
	}

	return repositories.PasswordCreateParams{
		UserID:            userID,
		CategoryID:        stringPointerOrNil(clean.Category),
		Website:           clean.Name,
		Username:          stringPointerOrNil(clean.Username),
		PasswordEncrypted: clean.EncryptedPassword,
		NotesEncrypted:    stringPointerOrNil(clean.Notes),
		URL:               stringPointerOrNil(clean.URL),
		PasswordStrength:  clean.StrengthScore,
	}, nil
}

func prepareFlutterPasswordUpdateParams(userID, passwordID string, input FlutterPasswordInput) (repositories.PasswordUpdateParams, error) {
	clean, err := normalizeFlutterPasswordInput(input)
	if err != nil {
		return repositories.PasswordUpdateParams{}, err
	}

	return repositories.PasswordUpdateParams{
		ID:                passwordID,
		UserID:            userID,
		CategoryID:        stringPointerOrNil(clean.Category),
		Website:           clean.Name,
		Username:          stringPointerOrNil(clean.Username),
		PasswordEncrypted: clean.EncryptedPassword,
		NotesEncrypted:    stringPointerOrNil(clean.Notes),
		URL:               stringPointerOrNil(clean.URL),
		PasswordStrength:  clean.StrengthScore,
	}, nil
}

func normalizeFlutterPasswordInput(input FlutterPasswordInput) (FlutterPasswordInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Username = strings.TrimSpace(input.Username)
	input.EncryptedPassword = strings.TrimSpace(input.EncryptedPassword)
	input.URL = strings.TrimSpace(input.URL)
	input.Category = strings.TrimSpace(input.Category)
	input.Notes = strings.TrimSpace(input.Notes)

	if input.Name == "" {
		return FlutterPasswordInput{}, fmt.Errorf("%w: name is required", ErrInvalidVaultPayload)
	}
	if input.EncryptedPassword == "" {
		return FlutterPasswordInput{}, fmt.Errorf("%w: encryptedPassword is required", ErrInvalidVaultPayload)
	}
	if input.StrengthScore < 0 {
		input.StrengthScore = 0
	}
	if input.StrengthScore > 100 {
		input.StrengthScore = 100
	}

	return input, nil
}

func toFlutterPasswordListItem(record repositories.PasswordRecord, categoryNames map[string]string) FlutterPasswordListItem {
	return FlutterPasswordListItem{
		ID:                record.ID,
		Name:              record.Website,
		Username:          stringFromPointer(record.Username),
		EncryptedPassword: record.PasswordEncrypted,
		URL:               stringFromPointer(record.URL),
		Notes:             stringFromPointer(record.NotesEncrypted),
		Category:          lookupCategoryName(record.CategoryID, categoryNames),
		StrengthScore:     record.PasswordStrength,
		CreatedAt:         record.CreatedAt,
		UpdatedAt:         record.UpdatedAt,
	}
}

func toFlutterPasswordDetail(record repositories.PasswordRecord, categoryNames map[string]string) FlutterPasswordDetail {
	return FlutterPasswordDetail{
		ID:                record.ID,
		Name:              record.Website,
		Username:          stringFromPointer(record.Username),
		EncryptedPassword: record.PasswordEncrypted,
		URL:               stringFromPointer(record.URL),
		Notes:             stringFromPointer(record.NotesEncrypted),
		Category:          lookupCategoryName(record.CategoryID, categoryNames),
		StrengthScore:     record.PasswordStrength,
		CreatedAt:         record.CreatedAt,
		UpdatedAt:         record.UpdatedAt,
	}
}

func (s *VaultService) categoryNamesByID(ctx context.Context, userID string) (map[string]string, error) {
	if s.categories == nil {
		return map[string]string{}, nil
	}

	items, err := s.categories.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	results := make(map[string]string, len(items))
	for _, item := range items {
		results[item.ID] = item.Name
	}

	return results, nil
}

func (s *VaultService) resolveFlutterCategoryID(ctx context.Context, userID, categoryName string) (*string, error) {
	if s.categories == nil {
		return nil, nil
	}

	categoryName = strings.TrimSpace(categoryName)
	if categoryName == "" {
		return nil, nil
	}

	items, err := s.categories.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if strings.EqualFold(item.Name, categoryName) {
			return &item.ID, nil
		}
	}

	category, err := s.categories.Create(ctx, repositories.CategoryParams{
		UserID: userID,
		Name:   categoryName,
	})
	if err != nil {
		return nil, err
	}
	return &category.ID, nil
}

func lookupCategoryName(categoryID *string, categoryNames map[string]string) string {
	if categoryID == nil {
		return ""
	}
	if name, ok := categoryNames[*categoryID]; ok {
		return name
	}
	return ""
}

func stringPointerOrNil(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func stringFromPointer(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
