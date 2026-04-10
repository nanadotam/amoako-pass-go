package handlers

import (
	"errors"
	"net/http"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type UtilityHandler struct {
	hibp *services.HIBPService
}

func NewUtilityHandler(hibp *services.HIBPService) *UtilityHandler {
	return &UtilityHandler{hibp: hibp}
}

func (h *UtilityHandler) HIBPCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := apicontext.UserID(r.Context()); !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}

	var input struct {
		HashPrefix string `json:"hash_prefix"`
	}
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	result, err := h.hibp.CheckPrefix(r.Context(), input.HashPrefix)
	if err != nil {
		if errors.Is(err, services.ErrInvalidVaultPayload) {
			respond.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		respond.Error(w, http.StatusBadGateway, "hibp request failed")
		return
	}

	respond.JSON(w, http.StatusOK, map[string]string{"result": result})
}
