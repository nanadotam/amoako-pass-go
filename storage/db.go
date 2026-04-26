package storage

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"

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

	connStr = forcePublicSchema(connStr)

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

// forcePublicSchema injects search_path=public into every connection opened
// from this pool. This overrides any role-level default (e.g. keysafe_app
// was configured with search_path=keysafe,public which caused queries to
// silently land in the wrong schema).
func forcePublicSchema(connStr string) string {
	if strings.Contains(connStr, "search_path") {
		return connStr
	}
	if strings.HasPrefix(connStr, "postgres://") || strings.HasPrefix(connStr, "postgresql://") {
		u, err := url.Parse(connStr)
		if err != nil {
			return connStr
		}
		q := u.Query()
		existing := q.Get("options")
		if existing == "" {
			q.Set("options", "-c search_path=public")
		} else {
			q.Set("options", existing+" -c search_path=public")
		}
		u.RawQuery = q.Encode()
		return u.String()
	}
	return connStr + " options='-c search_path=public'"
}
