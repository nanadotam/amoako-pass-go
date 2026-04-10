package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HIBPService struct {
	client         *http.Client
	requestTimeout time.Duration
}

func NewHIBPService(requestTimeout time.Duration) *HIBPService {
	return &HIBPService{
		client:         &http.Client{Timeout: requestTimeout},
		requestTimeout: requestTimeout,
	}
}

func (s *HIBPService) CheckPrefix(ctx context.Context, prefix string) (string, error) {
	prefix = strings.TrimSpace(strings.ToUpper(prefix))
	if len(prefix) != 5 {
		return "", fmt.Errorf("%w: hash_prefix must be 5 characters", ErrInvalidVaultPayload)
	}

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix, nil)
	if err != nil {
		return "", fmt.Errorf("build hibp request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send hibp request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read hibp response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hibp returned status %d", resp.StatusCode)
	}
	return string(body), nil
}
