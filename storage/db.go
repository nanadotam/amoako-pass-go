package storage

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

func ConnectDB(connStr string) (*sql.DB, error) {
	return connectDB(connStr, false)
}

func ConnectDBWithMode(connStr string, noDB bool) (*sql.DB, error) {
	return connectDB(connStr, noDB)
}

func connectDB(connStr string, noDB bool) (*sql.DB, error) {
	if noDB {
		return nil, nil
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres connection: %w", err)
	}

	return db, nil
}
