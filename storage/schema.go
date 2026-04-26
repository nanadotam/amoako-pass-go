package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type requiredTable struct {
	name    string
	columns []string
}

var requiredPublicTables = []requiredTable{
	{
		name: "users",
		columns: []string{
			"id", "email", "username", "first_name", "last_name",
			"password_hash", "created_at", "updated_at", "last_login",
		},
	},
	{
		name: "user_sessions",
		columns: []string{
			"id", "user_id", "session_token", "ip_address", "user_agent",
			"expires_at", "created_at", "last_accessed", "is_active",
		},
	},
	{
		name: "passwords",
		columns: []string{
			"id", "user_id", "category_id", "website", "username", "email",
			"password_encrypted", "notes_encrypted", "url", "is_favorite",
			"password_strength", "tags", "created_at", "updated_at",
			"accessed_at", "access_count",
		},
	},
	{
		name: "wifi_passwords",
		columns: []string{
			"id", "user_id", "network_name", "password_encrypted",
			"security_type", "notes_encrypted", "location", "is_favorite",
			"created_at", "updated_at", "accessed_at", "access_count",
		},
	},
	{
		name: "categories",
		columns: []string{
			"id", "user_id", "name", "color", "icon", "is_default",
			"sort_order", "created_at", "updated_at",
		},
	},
	{
		name: "login_history",
		columns: []string{
			"id", "user_id", "logged_at", "latitude", "longitude", "city",
			"country", "is_trusted", "ip_address", "user_agent",
		},
	},
	{
		name: "audit_logs",
		columns: []string{
			"id", "user_id", "action", "resource_type", "resource_id",
			"details", "created_at", "ip_address", "user_agent",
		},
	},
}

func ValidateSchema(ctx context.Context, db *sql.DB) error {
	for _, table := range requiredPublicTables {
		exists, err := tableExists(ctx, db, "public", table.name)
		if err != nil {
			return fmt.Errorf("check table %s: %w", table.name, err)
		}
		if !exists {
			return fmt.Errorf("required table public.%s is missing", table.name)
		}

		missing, err := missingColumns(ctx, db, "public", table.name, table.columns)
		if err != nil {
			return fmt.Errorf("check columns for table %s: %w", table.name, err)
		}
		if len(missing) > 0 {
			return fmt.Errorf(
				"required columns missing from public.%s: %s",
				table.name,
				strings.Join(missing, ", "),
			)
		}
	}

	return nil
}

func tableExists(ctx context.Context, db *sql.DB, schema, table string) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = $1 AND table_name = $2
		)
	`
	var exists bool
	if err := db.QueryRowContext(ctx, query, schema, table).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func missingColumns(ctx context.Context, db *sql.DB, schema, table string, required []string) ([]string, error) {
	const query = `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
	`

	rows, err := db.QueryContext(ctx, query, schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	available := make(map[string]struct{}, len(required))
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		available[column] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var missing []string
	for _, column := range required {
		if _, ok := available[column]; !ok {
			missing = append(missing, column)
		}
	}
	return missing, nil
}
