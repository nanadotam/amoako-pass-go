package handlers

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/repositories"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type AuthHandler struct {
	service     *services.AuthService
	maintenance *services.MaintenanceService
	audit       *services.AuditService
	loginLimits *services.RateLimiter
}

func NewAuthHandler(service *services.AuthService, maintenance *services.MaintenanceService, audit *services.AuditService, loginLimits *services.RateLimiter) *AuthHandler {
	return &AuthHandler{
		service:     service,
		maintenance: maintenance,
		audit:       audit,
		loginLimits: loginLimits,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input services.RegisterInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	result, err := h.service.Register(r.Context(), input, requestAuthMeta(r))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAuthPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, repositories.ErrUserConflict):
			respond.Error(w, http.StatusConflict, "email or username already exists")
		default:
			log.Printf("auth register failed: email=%q username=%q err=%v", input.Email, input.Username, err)
			respond.Error(w, http.StatusInternalServerError, fmt.Sprintf("registration failed: %v", err))
		}
		return
	}

	respond.JSON(w, http.StatusCreated, result)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input services.LoginInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	limitKey := loginLimitKey(r, input.Email)
	if h.loginLimits != nil && !h.loginLimits.Allow(limitKey) {
		respond.Error(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}

	result, err := h.service.Login(r.Context(), input, requestAuthMeta(r))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAuthPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrInvalidCredentials):
			if h.loginLimits != nil {
				h.loginLimits.RecordFailure(limitKey)
			}
			respond.Error(w, http.StatusUnauthorized, err.Error())
		default:
			log.Printf("auth login failed: email=%q err=%v", input.Email, err)
			respond.Error(w, http.StatusInternalServerError, "login failed")
		}
		return
	}

	if h.loginLimits != nil {
		h.loginLimits.Reset(limitKey)
	}
	h.writeAudit(r, result.User.ID, "login", "", "", map[string]any{"email": result.User.Email})
	respond.JSON(w, http.StatusOK, result)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var input services.RefreshInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	result, err := h.service.Refresh(r.Context(), input, requestAuthMeta(r))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAuthPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrInvalidRefreshToken):
			respond.Error(w, http.StatusUnauthorized, err.Error())
		default:
			respond.Error(w, http.StatusInternalServerError, "refresh failed")
		}
		return
	}

	respond.JSON(w, http.StatusOK, result)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.LogoutInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if err := h.service.Logout(r.Context(), userID, input); err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAuthPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrInvalidRefreshToken):
			respond.Error(w, http.StatusUnauthorized, err.Error())
		default:
			respond.Error(w, http.StatusInternalServerError, "logout failed")
		}
		return
	}

	h.writeAudit(r, userID, "logout", "session", "", nil)
	respond.JSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.ChangePasswordInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if err := h.service.ChangePassword(r.Context(), userID, input); err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAuthPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrInvalidCredentials):
			respond.Error(w, http.StatusUnauthorized, err.Error())
		default:
			respond.Error(w, http.StatusInternalServerError, "change password failed")
		}
		return
	}

	if h.maintenance != nil {
		if err := h.maintenance.Rekey(r.Context(), userID); err != nil {
			respond.Error(w, http.StatusInternalServerError, "password changed but rekey failed")
			return
		}
	}

	h.writeAudit(r, userID, "password_changed", "user", userID, nil)
	respond.JSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

func (h *AuthHandler) writeAudit(r *http.Request, userID, action, resourceType, resourceID string, details map[string]any) {
	if h.audit == nil {
		return
	}
	meta := requestAuthMeta(r)
	_ = h.audit.Write(r.Context(), services.AuditEntry{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IP:           meta.IP,
		UserAgent:    meta.UserAgent,
		Details:      details,
	})
}

func requestAuthMeta(r *http.Request) services.AuthMeta {
	return services.AuthMeta{
		IP:        requestIP(r),
		UserAgent: trimStringPointer(r.UserAgent()),
	}
}

func requestIP(r *http.Request) *string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return trimStringPointer(parts[0])
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return &host
	}
	return trimStringPointer(r.RemoteAddr)
}

func loginLimitKey(r *http.Request, email string) string {
	ip := ""
	if value := requestIP(r); value != nil {
		ip = *value
	}
	return strings.ToLower(strings.TrimSpace(email)) + "|" + ip
}

func trimStringPointer(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
