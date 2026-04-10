package services

import (
	"context"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/repositories"
)

type MaintenanceService struct {
	passwords      passwordStore
	wifi           wifiStore
	encryption     *EncryptionService
	requestTimeout time.Duration
}

func NewMaintenanceService(passwords passwordStore, wifi wifiStore, encryption *EncryptionService, requestTimeout time.Duration) *MaintenanceService {
	return &MaintenanceService{
		passwords:      passwords,
		wifi:           wifi,
		encryption:     encryption,
		requestTimeout: requestTimeout,
	}
}

func (s *MaintenanceService) Rekey(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	passwords, err := s.passwords.ListByUser(ctx, repositories.PasswordListOptions{UserID: userID})
	if err != nil {
		return err
	}
	for _, record := range passwords {
		password, err := s.encryption.Decrypt(record.PasswordEncrypted)
		if err != nil {
			return err
		}
		passwordEncrypted, err := s.encryption.Encrypt(password)
		if err != nil {
			return err
		}
		var notesEncrypted *string
		if record.NotesEncrypted != nil {
			notes, err := s.encryption.Decrypt(*record.NotesEncrypted)
			if err != nil {
				return err
			}
			recrypted, err := s.encryption.Encrypt(notes)
			if err != nil {
				return err
			}
			notesEncrypted = &recrypted
		}
		if _, err := s.passwords.Update(ctx, repositories.PasswordUpdateParams{
			ID:                record.ID,
			UserID:            userID,
			CategoryID:        record.CategoryID,
			Website:           record.Website,
			Username:          record.Username,
			Email:             record.Email,
			PasswordEncrypted: passwordEncrypted,
			NotesEncrypted:    notesEncrypted,
			URL:               record.URL,
			IsFavorite:        record.IsFavorite,
			PasswordStrength:  record.PasswordStrength,
			Tags:              record.Tags,
		}); err != nil {
			return err
		}
	}

	wifiItems, err := s.wifi.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, record := range wifiItems {
		password, err := s.encryption.Decrypt(record.PasswordEncrypted)
		if err != nil {
			return err
		}
		passwordEncrypted, err := s.encryption.Encrypt(password)
		if err != nil {
			return err
		}
		var notesEncrypted *string
		if record.NotesEncrypted != nil {
			notes, err := s.encryption.Decrypt(*record.NotesEncrypted)
			if err != nil {
				return err
			}
			recrypted, err := s.encryption.Encrypt(notes)
			if err != nil {
				return err
			}
			notesEncrypted = &recrypted
		}
		if _, err := s.wifi.Update(ctx, repositories.WifiUpdateParams{
			ID:                record.ID,
			UserID:            userID,
			NetworkName:       record.NetworkName,
			PasswordEncrypted: passwordEncrypted,
			SecurityType:      record.SecurityType,
			NotesEncrypted:    notesEncrypted,
			Location:          record.Location,
			IsFavorite:        record.IsFavorite,
		}); err != nil {
			return err
		}
	}

	return nil
}
