package handlers

import (
	"errors"
	"net/http"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/repositories"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type CategoryHandler struct {
	service *services.CategoryService
}

func NewCategoryHandler(service *services.CategoryService) *CategoryHandler {
	return &CategoryHandler{service: service}
}

func (h *CategoryHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	items, err := h.service.List(r.Context(), userID)
	if err != nil {
		respond.Error(w, http.StatusInternalServerError, "failed to list categories")
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *CategoryHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	var input services.CategoryInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	item, err := h.service.Create(r.Context(), userID, input)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidVaultPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, repositories.ErrUserConflict):
			respond.Error(w, http.StatusConflict, "category already exists")
		default:
			respond.Error(w, http.StatusInternalServerError, "failed to create category")
		}
		return
	}
	respond.JSON(w, http.StatusCreated, item)
}

func (h *CategoryHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	var input services.CategoryInput
	if err := respond.DecodeJSON(r, &input); err != nil {
		respond.Error(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	item, err := h.service.Update(r.Context(), userID, r.PathValue("id"), input)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidVaultPayload):
			respond.Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, repositories.ErrCategoryNotFound):
			respond.Error(w, http.StatusNotFound, "category not found")
		default:
			respond.Error(w, http.StatusInternalServerError, "failed to update category")
		}
		return
	}
	respond.JSON(w, http.StatusOK, item)
}

func (h *CategoryHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, ok := apicontext.UserID(r.Context())
	if !ok {
		respond.Error(w, http.StatusUnauthorized, "missing authenticated user")
		return
	}
	if err := h.service.Delete(r.Context(), userID, r.PathValue("id")); err != nil {
		if errors.Is(err, repositories.ErrCategoryNotFound) {
			respond.Error(w, http.StatusNotFound, "category not found")
			return
		}
		respond.Error(w, http.StatusInternalServerError, "failed to delete category")
		return
	}
	respond.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
