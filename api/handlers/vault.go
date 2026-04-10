package handlers

import (
	"errors"
	"net/http"
	"strings"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/repositories"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type VaultHandler struct {
	service     *services.VaultService
	maintenance *services.MaintenanceService
	transfer    *services.TransferService
	audit       *services.AuditService
}

func NewVaultHandler(service *services.VaultService, maintenance *services.MaintenanceService, transfer *services.TransferService, audit *services.AuditService) *VaultHandler {
	return &VaultHandler{
		service:     service,
		maintenance: maintenance,
		transfer:    transfer,
		audit:       audit,
	}
}

func (h *VaultHandler) ListPasswords(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	items, err := h.service.List(r.Context(), userID, services.PasswordListQuery{
		CategoryID: r.URL.Query().Get("category_id"),
		Search:     r.URL.Query().Get("search"),
	})
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list passwords")
		return
	}

	respond.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *VaultHandler) CreatePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.PasswordInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	item, err := h.service.Create(r.Context(), userID, input)
	if err != nil {
		if errors.Is(err, services.ErrInvalidVaultPayload) {
			respond.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to create password")
		return
	}

	h.writeAudit(r, userID, "password_created", "password", item.ID, map[string]any{"website": item.Website})
	respond.JSON(w, http.StatusCreated, item)
}

func (h *VaultHandler) GetPassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	passwordID := r.PathValue("id")
	item, err := h.service.Get(r.Context(), userID, passwordID)
	if err != nil {
		if errors.Is(err, repositories.ErrPasswordNotFound) {
			respond.Error(w, http.StatusNotFound, "password entry not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to fetch password")
		return
	}

	respond.JSON(w, http.StatusOK, item)
}

func (h *VaultHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.PasswordInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	item, err := h.service.Update(r.Context(), userID, r.PathValue("id"), input)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidVaultPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, repositories.ErrPasswordNotFound):
			respond.Error(w, http.StatusNotFound, "password entry not found")
		default:
			respond.Error(w, http.StatusInternalServerError, "failed to update password")
		}
		return
	}

	h.writeAudit(r, userID, "password_updated", "password", item.ID, map[string]any{"website": item.Website})
	respond.JSON(w, http.StatusOK, item)
}

func (h *VaultHandler) DeletePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	passwordID := r.PathValue("id")
	if err := h.service.Delete(r.Context(), userID, passwordID); err != nil {
		if errors.Is(err, repositories.ErrPasswordNotFound) {
			respond.Error(w, http.StatusNotFound, "password entry not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to delete password")
		return
	}

	h.writeAudit(r, userID, "password_deleted", "password", passwordID, nil)
	respond.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *VaultHandler) FlutterListPasswords(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	items, err := h.service.FlutterList(r.Context(), userID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list passwords")
		return
	}

	respond.JSON(w, http.StatusOK, map[string]any{"entries": items})
}

func (h *VaultHandler) FlutterCreatePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.FlutterPasswordInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	item, err := h.service.FlutterCreate(r.Context(), userID, input)
	if err != nil {
		if errors.Is(err, services.ErrInvalidVaultPayload) {
			respond.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to create password")
		return
	}

	h.writeAudit(r, userID, "password_created", "password", item.ID, map[string]any{"website": item.Name})
	respond.JSON(w, http.StatusCreated, item)
}

func (h *VaultHandler) FlutterGetPassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	item, err := h.service.FlutterGet(r.Context(), userID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, repositories.ErrPasswordNotFound) {
			respond.Error(w, http.StatusNotFound, "password entry not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to fetch password")
		return
	}

	respond.JSON(w, http.StatusOK, item)
}

func (h *VaultHandler) FlutterUpdatePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.FlutterPasswordInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	item, err := h.service.FlutterUpdate(r.Context(), userID, r.PathValue("id"), input)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidVaultPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, repositories.ErrPasswordNotFound):
			respond.Error(w, http.StatusNotFound, "password entry not found")
		default:
			respond.Error(w, http.StatusInternalServerError, "failed to update password")
		}
		return
	}

	h.writeAudit(r, userID, "password_updated", "password", item.ID, map[string]any{"website": item.Name})
	respond.JSON(w, http.StatusOK, item)
}

func (h *VaultHandler) Rekey(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	if h.maintenance == nil {
		respond.Error(w, http.StatusServiceUnavailable, "vault rekey is unavailable")
		return
	}
	if err := h.maintenance.Rekey(r.Context(), userID); err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to rekey vault")
		return
	}
	h.writeAudit(r, userID, "vault_rekeyed", "vault", "", nil)
	respond.JSON(w, http.StatusOK, map[string]string{"status": "rekeyed"})
}

func (h *VaultHandler) Export(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	format := strings.TrimSpace(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	encrypted := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("encrypted")), "true")

	payload, contentType, err := h.transfer.Export(r.Context(), userID, format, encrypted)
	if err != nil {
		if errors.Is(err, services.ErrInvalidVaultPayload) {
			respond.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to export vault")
		return
	}

	h.writeAudit(r, userID, "vault_exported", "vault", "", map[string]any{"format": format, "encrypted": encrypted})
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (h *VaultHandler) Import(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	var input services.ImportRequest
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	result, err := h.transfer.Import(r.Context(), userID, input)
	if err != nil {
		if errors.Is(err, services.ErrInvalidVaultPayload) {
			respond.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to import vault data")
		return
	}

	h.writeAudit(r, userID, "vault_imported", "vault", "", map[string]any{"format": input.Format, "imported": result.Imported, "skipped": result.Skipped})
	respond.JSON(w, http.StatusOK, result)
}

func (h *VaultHandler) writeAudit(r *http.Request, userID, action, resourceType, resourceID string, details map[string]any) {
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
