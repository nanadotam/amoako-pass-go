package handlers

import (
	"errors"
	"net/http"
	"strconv"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/repositories"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type UserHandler struct {
	service  *services.UserService
	sessions *services.SessionService
}

func NewUserHandler(service *services.UserService, sessions *services.SessionService) *UserHandler {
	return &UserHandler{service: service, sessions: sessions}
}

func (h *UserHandler) Profile(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	profile, err := h.service.Profile(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repositories.ErrUserNotFound) {
			respond.Error(w, http.StatusNotFound, "user not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to load profile")
		return
	}

	respond.JSON(w, http.StatusOK, profile)
}

func (h *UserHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	items, err := h.sessions.List(r.Context(), userID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}

	response := make([]map[string]any, 0, len(items))
	for _, item := range items {
		response = append(response, map[string]any{
			"session_id":  item.ID,
			"device_hint": item.UserAgent,
			"ip":          item.IP,
			"created_at":  item.CreatedAt,
			"last_seen":   item.LastAccessed,
			"expires_at":  item.ExpiresAt,
		})
	}

	respond.JSON(w, http.StatusOK, map[string]any{"items": response})
}

func (h *UserHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	if err := h.sessions.Revoke(r.Context(), userID, r.PathValue("id")); err != nil {
		if errors.Is(err, repositories.ErrSessionNotFound) {
			respond.Error(w, http.StatusNotFound, "session not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to revoke session")
		return
	}
	respond.JSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func intQuery(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
