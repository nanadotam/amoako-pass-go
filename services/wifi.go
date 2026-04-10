package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type wifiStore interface {
	ListByUser(ctx context.Context, userID string) ([]repositories.WifiRecord, error)
	FindByID(ctx context.Context, userID, wifiID string) (*repositories.WifiRecord, error)
	Create(ctx context.Context, params repositories.WifiCreateParams) (*repositories.WifiRecord, error)
	Update(ctx context.Context, params repositories.WifiUpdateParams) (*repositories.WifiRecord, error)
	Delete(ctx context.Context, userID, wifiID string) error
}

type WifiService struct {
	wifi           wifiStore
	encryption     *EncryptionService
	requestTimeout time.Duration
}

type WifiInput struct {
	SSID         string  `json:"ssid"`
	Password     string  `json:"password"`
	SecurityType string  `json:"security_type"`
	Notes        *string `json:"notes"`
	Location     *string `json:"location"`
	IsFavorite   bool    `json:"is_favorite"`
}

type WifiDetail struct {
	ID           string    `json:"id"`
	SSID         string    `json:"ssid"`
	Password     string    `json:"password"`
	SecurityType string    `json:"security_type"`
	Notes        *string   `json:"notes,omitempty"`
	Location     *string   `json:"location,omitempty"`
	IsFavorite   bool      `json:"is_favorite"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type FlutterWifiInput struct {
	ID                string     `json:"id,omitempty"`
	NetworkName       string     `json:"networkName"`
	EncryptedPassword string     `json:"encryptedPassword"`
	Notes             string     `json:"notes"`
	CreatedAt         *time.Time `json:"createdAt,omitempty"`
	UpdatedAt         *time.Time `json:"updatedAt,omitempty"`
}

type FlutterWifiDetail struct {
	ID                string    `json:"id"`
	NetworkName       string    `json:"networkName"`
	EncryptedPassword string    `json:"encryptedPassword"`
	Notes             string    `json:"notes"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

const defaultFlutterWifiSecurityType = "WPA/WPA2"

func NewWifiService(wifi wifiStore, encryption *EncryptionService, requestTimeout time.Duration) *WifiService {
	return &WifiService{wifi: wifi, encryption: encryption, requestTimeout: requestTimeout}
}

func (s *WifiService) List(ctx context.Context, userID string) ([]WifiDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	records, err := s.wifi.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	items := make([]WifiDetail, 0, len(records))
	for _, record := range records {
		item, err := s.toDetail(&record)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, nil
}

func (s *WifiService) Get(ctx context.Context, userID, wifiID string) (*WifiDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	record, err := s.wifi.FindByID(ctx, userID, wifiID)
	if err != nil {
		return nil, err
	}
	return s.toDetail(record)
}

func (s *WifiService) Create(ctx context.Context, userID string, input WifiInput) (*WifiDetail, error) {
	clean, err := normalizeWifiInput(input)
	if err != nil {
		return nil, err
	}

	passwordEncrypted, err := s.encryption.Encrypt(clean.Password)
	if err != nil {
		return nil, fmt.Errorf("encrypt wifi password: %w", err)
	}
	var notesEncrypted *string
	if clean.Notes != nil {
		encrypted, err := s.encryption.Encrypt(*clean.Notes)
		if err != nil {
			return nil, fmt.Errorf("encrypt wifi notes: %w", err)
		}
		notesEncrypted = &encrypted
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	record, err := s.wifi.Create(ctx, repositories.WifiCreateParams{
		UserID:            userID,
		NetworkName:       clean.SSID,
		PasswordEncrypted: passwordEncrypted,
		SecurityType:      clean.SecurityType,
		NotesEncrypted:    notesEncrypted,
		Location:          clean.Location,
		IsFavorite:        clean.IsFavorite,
	})
	if err != nil {
		return nil, err
	}
	return s.toDetail(record)
}

func (s *WifiService) Update(ctx context.Context, userID, wifiID string, input WifiInput) (*WifiDetail, error) {
	clean, err := normalizeWifiInput(input)
	if err != nil {
		return nil, err
	}

	passwordEncrypted, err := s.encryption.Encrypt(clean.Password)
	if err != nil {
		return nil, fmt.Errorf("encrypt wifi password: %w", err)
	}
	var notesEncrypted *string
	if clean.Notes != nil {
		encrypted, err := s.encryption.Encrypt(*clean.Notes)
		if err != nil {
			return nil, fmt.Errorf("encrypt wifi notes: %w", err)
		}
		notesEncrypted = &encrypted
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	record, err := s.wifi.Update(ctx, repositories.WifiUpdateParams{
		ID:                wifiID,
		UserID:            userID,
		NetworkName:       clean.SSID,
		PasswordEncrypted: passwordEncrypted,
		SecurityType:      clean.SecurityType,
		NotesEncrypted:    notesEncrypted,
		Location:          clean.Location,
		IsFavorite:        clean.IsFavorite,
	})
	if err != nil {
		return nil, err
	}
	return s.toDetail(record)
}

func (s *WifiService) Delete(ctx context.Context, userID, wifiID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()
	return s.wifi.Delete(ctx, userID, wifiID)
}

func (s *WifiService) FlutterList(ctx context.Context, userID string) ([]FlutterWifiDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	records, err := s.wifi.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	items := make([]FlutterWifiDetail, 0, len(records))
	for _, record := range records {
		items = append(items, toFlutterWifiDetail(record))
	}

	return items, nil
}

func (s *WifiService) FlutterGet(ctx context.Context, userID, wifiID string) (*FlutterWifiDetail, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.wifi.FindByID(ctx, userID, wifiID)
	if err != nil {
		return nil, err
	}

	item := toFlutterWifiDetail(*record)
	return &item, nil
}

func (s *WifiService) FlutterCreate(ctx context.Context, userID string, input FlutterWifiInput) (*FlutterWifiDetail, error) {
	clean, err := normalizeFlutterWifiInput(input)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	record, err := s.wifi.Create(ctx, repositories.WifiCreateParams{
		UserID:            userID,
		NetworkName:       clean.NetworkName,
		PasswordEncrypted: clean.EncryptedPassword,
		SecurityType:      defaultFlutterWifiSecurityType,
		NotesEncrypted:    stringPointerOrNil(clean.Notes),
	})
	if err != nil {
		return nil, err
	}

	item := toFlutterWifiDetail(*record)
	return &item, nil
}

func (s *WifiService) FlutterUpdate(ctx context.Context, userID, wifiID string, input FlutterWifiInput) (*FlutterWifiDetail, error) {
	clean, err := normalizeFlutterWifiInput(input)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	existing, err := s.wifi.FindByID(ctx, userID, wifiID)
	if err != nil {
		return nil, err
	}

	securityType := existing.SecurityType
	if strings.TrimSpace(securityType) == "" {
		securityType = defaultFlutterWifiSecurityType
	}

	record, err := s.wifi.Update(ctx, repositories.WifiUpdateParams{
		ID:                wifiID,
		UserID:            userID,
		NetworkName:       clean.NetworkName,
		PasswordEncrypted: clean.EncryptedPassword,
		SecurityType:      securityType,
		NotesEncrypted:    stringPointerOrNil(clean.Notes),
		Location:          existing.Location,
		IsFavorite:        existing.IsFavorite,
	})
	if err != nil {
		return nil, err
	}

	item := toFlutterWifiDetail(*record)
	return &item, nil
}

func (s *WifiService) toDetail(record *repositories.WifiRecord) (*WifiDetail, error) {
	password, err := s.encryption.Decrypt(record.PasswordEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt wifi password: %w", err)
	}
	var notes *string
	if record.NotesEncrypted != nil {
		decrypted, err := s.encryption.Decrypt(*record.NotesEncrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt wifi notes: %w", err)
		}
		notes = &decrypted
	}
	return &WifiDetail{
		ID:           record.ID,
		SSID:         record.NetworkName,
		Password:     password,
		SecurityType: record.SecurityType,
		Notes:        notes,
		Location:     record.Location,
		IsFavorite:   record.IsFavorite,
		CreatedAt:    record.CreatedAt,
		UpdatedAt:    record.UpdatedAt,
	}, nil
}

func normalizeWifiInput(input WifiInput) (WifiInput, error) {
	input.SSID = strings.TrimSpace(input.SSID)
	input.SecurityType = strings.TrimSpace(input.SecurityType)
	if input.SSID == "" {
		return WifiInput{}, fmt.Errorf("%w: ssid is required", ErrInvalidVaultPayload)
	}
	if strings.TrimSpace(input.Password) == "" && !strings.EqualFold(input.SecurityType, "Open") {
		return WifiInput{}, fmt.Errorf("%w: wifi password is required", ErrInvalidVaultPayload)
	}
	if input.SecurityType == "" {
		return WifiInput{}, fmt.Errorf("%w: security_type is required", ErrInvalidVaultPayload)
	}
	input.Notes = trimPointer(input.Notes)
	input.Location = trimPointer(input.Location)
	return input, nil
}

func normalizeFlutterWifiInput(input FlutterWifiInput) (FlutterWifiInput, error) {
	input.NetworkName = strings.TrimSpace(input.NetworkName)
	input.EncryptedPassword = strings.TrimSpace(input.EncryptedPassword)
	input.Notes = strings.TrimSpace(input.Notes)

	if input.NetworkName == "" {
		return FlutterWifiInput{}, fmt.Errorf("%w: networkName is required", ErrInvalidVaultPayload)
	}
	if input.EncryptedPassword == "" {
		return FlutterWifiInput{}, fmt.Errorf("%w: encryptedPassword is required", ErrInvalidVaultPayload)
	}

	return input, nil
}

func toFlutterWifiDetail(record repositories.WifiRecord) FlutterWifiDetail {
	return FlutterWifiDetail{
		ID:                record.ID,
		NetworkName:       record.NetworkName,
		EncryptedPassword: record.PasswordEncrypted,
		Notes:             stringFromPointer(record.NotesEncrypted),
		CreatedAt:         record.CreatedAt,
		UpdatedAt:         record.UpdatedAt,
	}
}
