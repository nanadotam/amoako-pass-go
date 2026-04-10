package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
)

type HealthHandler struct {
	db      *sql.DB
	version string
}

func NewHealthHandler(db *sql.DB, version string) *HealthHandler {
	return &HealthHandler{db: db, version: version}
}

func (h *HealthHandler) Check(w http.ResponseWriter, _ *http.Request) {
	status := "connected"
	if h.db == nil {
		status = "disabled"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := h.db.PingContext(ctx); err != nil {
			status = "degraded"
		}
	}

	respond.JSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": h.version,
		"db":      status,
	})
}
