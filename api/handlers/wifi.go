package handlers

import (
	"errors"
	"net/http"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/repositories"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type WifiHandler struct {
	service *services.WifiService
	audit   *services.AuditService
}

func NewWifiHandler(service *services.WifiService, audit *services.AuditService) *WifiHandler {
	return &WifiHandler{service: service, audit: audit}
}

func (h *WifiHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	items, err := h.service.List(r.Context(), userID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list wifi entries")
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *WifiHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	var input services.WifiInput
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
		respond.Error(w, http.StatusInternalServerError, "failed to create wifi entry")
		return
	}
	h.writeAudit(r, userID, "wifi_created", "wifi_password", item.ID, map[string]any{"ssid": item.SSID})
	respond.JSON(w, http.StatusCreated, item)
}

func (h *WifiHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	item, err := h.service.Get(r.Context(), userID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, repositories.ErrWifiNotFound) {
			respond.Error(w, http.StatusNotFound, "wifi entry not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to fetch wifi entry")
		return
	}
	respond.JSON(w, http.StatusOK, item)
}

func (h *WifiHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	var input services.WifiInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	item, err := h.service.Update(r.Context(), userID, r.PathValue("id"), input)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidVaultPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, repositories.ErrWifiNotFound):
			respond.Error(w, http.StatusNotFound, "wifi entry not found")
		default:
			respond.Error(w, http.StatusInternalServerError, "failed to update wifi entry")
		}
		return
	}
	h.writeAudit(r, userID, "wifi_updated", "wifi_password", item.ID, map[string]any{"ssid": item.SSID})
	respond.JSON(w, http.StatusOK, item)
}

func (h *WifiHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	wifiID := r.PathValue("id")
	if err := h.service.Delete(r.Context(), userID, wifiID); err != nil {
		if errors.Is(err, repositories.ErrWifiNotFound) {
			respond.Error(w, http.StatusNotFound, "wifi entry not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to delete wifi entry")
		return
	}
	h.writeAudit(r, userID, "wifi_deleted", "wifi_password", wifiID, nil)
	respond.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *WifiHandler) FlutterList(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	items, err := h.service.FlutterList(r.Context(), userID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list wifi entries")
		return
	}

	respond.JSON(w, http.StatusOK, map[string]any{"entries": items})
}

func (h *WifiHandler) FlutterCreate(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.FlutterWifiInput
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
		respond.Error(w, http.StatusInternalServerError, "failed to create wifi entry")
		return
	}

	h.writeAudit(r, userID, "wifi_created", "wifi_password", item.ID, map[string]any{"network_name": item.NetworkName})
	respond.JSON(w, http.StatusCreated, item)
}

func (h *WifiHandler) FlutterGet(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	item, err := h.service.FlutterGet(r.Context(), userID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, repositories.ErrWifiNotFound) {
			respond.Error(w, http.StatusNotFound, "wifi entry not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to fetch wifi entry")
		return
	}

	respond.JSON(w, http.StatusOK, item)
}

func (h *WifiHandler) FlutterUpdate(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input services.FlutterWifiInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	item, err := h.service.FlutterUpdate(r.Context(), userID, r.PathValue("id"), input)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidVaultPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, repositories.ErrWifiNotFound):
			respond.Error(w, http.StatusNotFound, "wifi entry not found")
		default:
			respond.Error(w, http.StatusInternalServerError, "failed to update wifi entry")
		}
		return
	}

	h.writeAudit(r, userID, "wifi_updated", "wifi_password", item.ID, map[string]any{"network_name": item.NetworkName})
	respond.JSON(w, http.StatusOK, item)
}

func (h *WifiHandler) writeAudit(r *http.Request, userID, action, resourceType, resourceID string, details map[string]any) {
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
