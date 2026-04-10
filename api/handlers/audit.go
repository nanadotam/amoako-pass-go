package handlers

import (
	"net/http"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type AuditHandler struct {
	service *services.AuditService
}

func NewAuditHandler(service *services.AuditService) *AuditHandler {
	return &AuditHandler{service: service}
}

func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	if h.service == nil {
		respond.Error(w, http.StatusServiceUnavailable, "audit logs are unavailable")
		return
	}

	items, err := h.service.List(
		r.Context(),
		userID,
		r.URL.Query().Get("action"),
		intQuery(r.URL.Query().Get("page"), 1),
		intQuery(r.URL.Query().Get("per_page"), 20),
	)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	respond.JSON(w, http.StatusOK, map[string]any{"items": items})
}
