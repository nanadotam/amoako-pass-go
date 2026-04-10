package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DBURL              string
	NoDB               bool
	JWTSecret          string
	EncryptionKey      []byte
	ServerAddr         string
	AppVersion         string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	CORSAllowedOrigins []string
	ReadTimeout        time.Duration
	ReadHeaderTimeout  time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	RequestTimeout     time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		DBURL:              os.Getenv("DB_URL"),
		NoDB:               os.Getenv("NO_DB") == "true",
		JWTSecret:          os.Getenv("JWT_SECRET"),
		ServerAddr:         serverAddrFromEnv(),
		AppVersion:         envOrDefault("APP_VERSION", "dev"),
		AccessTokenTTL:     durationFromEnv("ACCESS_TOKEN_TTL_SECONDS", 24*time.Hour),
		RefreshTokenTTL:    durationFromEnv("REFRESH_TOKEN_TTL_SECONDS", 30*24*time.Hour),
		CORSAllowedOrigins: csvEnvOrDefault("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
		ReadTimeout:        durationFromEnv("SERVER_READ_TIMEOUT_SECONDS", 10*time.Second),
		ReadHeaderTimeout:  durationFromEnv("SERVER_READ_HEADER_TIMEOUT_SECONDS", 5*time.Second),
		WriteTimeout:       durationFromEnv("SERVER_WRITE_TIMEOUT_SECONDS", 15*time.Second),
		IdleTimeout:        durationFromEnv("SERVER_IDLE_TIMEOUT_SECONDS", 60*time.Second),
		RequestTimeout:     durationFromEnv("REQUEST_TIMEOUT_SECONDS", 5*time.Second),
	}

	encodedKey := os.Getenv("VAULT_ENCRYPTION_KEY")
	if encodedKey == "" {
		return Config{}, errors.New("VAULT_ENCRYPTION_KEY is required")
	}

	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return Config{}, fmt.Errorf("decode VAULT_ENCRYPTION_KEY: %w", err)
	}
	if len(key) != 32 {
		return Config{}, errors.New("VAULT_ENCRYPTION_KEY must decode to exactly 32 bytes for AES-256")
	}

	if !cfg.NoDB && cfg.DBURL == "" {
		return Config{}, errors.New("DB_URL is required")
	}
	if cfg.JWTSecret == "" {
		return Config{}, errors.New("JWT_SECRET is required")
	}

	cfg.EncryptionKey = key
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func serverAddrFromEnv() string {
	if value := strings.TrimSpace(os.Getenv("SERVER_ADDR")); value != "" {
		return value
	}
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		if strings.HasPrefix(port, ":") {
			return port
		}
		return ":" + port
	}
	return ":8000"
}

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return fallback
	}

	return time.Duration(seconds) * time.Second
}

func csvEnvOrDefault(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parts := strings.Split(value, ",")
	results := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			results = append(results, trimmed)
		}
	}
	if len(results) == 0 {
		return fallback
	}
	return results
}
