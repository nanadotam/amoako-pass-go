package services

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type TransferService struct {
	vault          *VaultService
	wifi           *WifiService
	encryption     *EncryptionService
	requestTimeout time.Duration
}

type ImportRequest struct {
	Format string `json:"format"`
	Data   string `json:"data"`
}

type ImportResult struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors"`
}

func NewTransferService(vault *VaultService, wifi *WifiService, encryption *EncryptionService, requestTimeout time.Duration) *TransferService {
	return &TransferService{vault: vault, wifi: wifi, encryption: encryption, requestTimeout: requestTimeout}
}

func (s *TransferService) Export(ctx context.Context, userID, format string, encrypted bool) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	passwordSummaries, err := s.vault.List(ctx, userID, PasswordListQuery{})
	if err != nil {
		return nil, "", err
	}
	passwords := make([]*PasswordDetail, 0, len(passwordSummaries))
	for _, item := range passwordSummaries {
		detail, err := s.vault.Get(ctx, userID, item.ID)
		if err != nil {
			return nil, "", err
		}
		passwords = append(passwords, detail)
	}
	wifiItems, err := s.wifi.List(ctx, userID)
	if err != nil {
		return nil, "", err
	}

	if strings.EqualFold(format, "csv") {
		var buffer bytes.Buffer
		writer := csv.NewWriter(&buffer)
		_ = writer.Write([]string{"type", "name", "username", "email", "password", "url", "notes", "category_id", "ssid", "security_type", "location"})
		for _, detail := range passwords {
			_ = writer.Write([]string{"password", detail.Website, deref(detail.Username), deref(detail.Email), detail.Password, deref(detail.URL), deref(detail.Notes), deref(detail.CategoryID), "", "", ""})
		}
		for _, item := range wifiItems {
			passwordValue := item.Password
			_ = writer.Write([]string{"wifi", "", "", "", passwordValue, "", deref(item.Notes), "", item.SSID, item.SecurityType, deref(item.Location)})
		}
		writer.Flush()
		return buffer.Bytes(), "text/csv", writer.Error()
	}

	payload := map[string]any{
		"passwords": passwords,
		"wifi":      wifiItems,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("marshal export payload: %w", err)
	}
	if encrypted {
		cipherText, err := s.encryption.Encrypt(string(data))
		if err != nil {
			return nil, "", fmt.Errorf("encrypt export payload: %w", err)
		}
		wrapped, err := json.MarshalIndent(map[string]any{
			"encrypted": true,
			"payload":   cipherText,
		}, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("marshal encrypted export wrapper: %w", err)
		}
		return wrapped, "application/json", nil
	}
	return data, "application/json", nil
}

func (s *TransferService) Import(ctx context.Context, userID string, request ImportRequest) (*ImportResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	format := strings.TrimSpace(strings.ToLower(request.Format))
	switch format {
	case "json":
		return s.importJSON(ctx, userID, request.Data)
	case "csv":
		return s.importCSV(ctx, userID, request.Data)
	default:
		return nil, fmt.Errorf("%w: unsupported import format", ErrInvalidVaultPayload)
	}
}

func (s *TransferService) importJSON(ctx context.Context, userID, payload string) (*ImportResult, error) {
	var encryptedWrapper struct {
		Encrypted bool   `json:"encrypted"`
		Payload   string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(payload), &encryptedWrapper); err == nil && encryptedWrapper.Encrypted && encryptedWrapper.Payload != "" {
		decrypted, err := s.encryption.Decrypt(encryptedWrapper.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid encrypted import payload", ErrInvalidVaultPayload)
		}
		payload = decrypted
	}

	var body struct {
		Passwords []PasswordInput `json:"passwords"`
		Wifi      []WifiInput     `json:"wifi"`
	}
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		return nil, fmt.Errorf("%w: invalid import JSON", ErrInvalidVaultPayload)
	}
	result := &ImportResult{}
	for _, item := range body.Passwords {
		if _, err := s.vault.Create(ctx, userID, item); err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Skipped++
			continue
		}
		result.Imported++
	}
	for _, item := range body.Wifi {
		if _, err := s.wifi.Create(ctx, userID, item); err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Skipped++
			continue
		}
		result.Imported++
	}
	return result, nil
}

func (s *TransferService) importCSV(ctx context.Context, userID, payload string) (*ImportResult, error) {
	reader := csv.NewReader(strings.NewReader(payload))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid import CSV", ErrInvalidVaultPayload)
	}
	result := &ImportResult{}
	for i, row := range records {
		if i == 0 || len(row) < 11 {
			continue
		}
		switch row[0] {
		case "password":
			input := PasswordInput{
				Website:    row[1],
				Username:   nilIfEmpty(row[2]),
				Email:      nilIfEmpty(row[3]),
				Password:   row[4],
				URL:        nilIfEmpty(row[5]),
				Notes:      nilIfEmpty(row[6]),
				CategoryID: nilIfEmpty(row[7]),
			}
			if _, err := s.vault.Create(ctx, userID, input); err != nil {
				result.Errors = append(result.Errors, err.Error())
				result.Skipped++
				continue
			}
			result.Imported++
		case "wifi":
			input := WifiInput{
				SSID:         row[8],
				SecurityType: row[9],
				Location:     nilIfEmpty(row[10]),
				Password:     row[4],
				Notes:        nilIfEmpty(row[6]),
			}
			if _, err := s.wifi.Create(ctx, userID, input); err != nil {
				result.Errors = append(result.Errors, err.Error())
				result.Skipped++
				continue
			}
			result.Imported++
		}
	}
	return result, nil
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nilIfEmpty(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
