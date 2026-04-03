package http

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/ports"
)

// Handler holds all HTTP handler dependencies.
type Handler struct {
	creator   ports.ClientCreator
	reader    ports.ClientReader
	validator ports.ClientValidator
	deleter   ports.ClientDeleter
	logger    logging.Logger
}

func NewHandler(
	creator ports.ClientCreator,
	reader ports.ClientReader,
	validator ports.ClientValidator,
	deleter ports.ClientDeleter,
	logger logging.Logger,
) *Handler {
	return &Handler{
		creator:   creator,
		reader:    reader,
		validator: validator,
		deleter:   deleter,
		logger:    logger,
	}
}

// CreateClient handles POST /clients.
func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	var req application.CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.creator.CreateClient(r.Context(), req)
	if err != nil {
		h.logger.Error("create client failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, err.Error()))
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// ListClients handles GET /clients.
func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	resp, err := h.reader.ListClients(r.Context())
	if err != nil {
		h.logger.Error("list clients failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, err.Error()))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// GetClient handles GET /clients/{id}.
func (h *Handler) GetClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "client id is required"))
		return
	}

	resp, err := h.reader.GetClient(r.Context(), id)
	if err != nil {
		h.logger.Error("get client failed", "error", err.Error())
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// DeleteClient handles DELETE /clients/{id}.
func (h *Handler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "client id is required"))
		return
	}

	if err := h.deleter.DeleteClient(r.Context(), id); err != nil {
		h.logger.Error("delete client failed", "error", err.Error())
		httputil.WriteError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ValidateClient handles POST /clients/validate.
func (h *Handler) ValidateClient(w http.ResponseWriter, r *http.Request) {
	var req application.ValidateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.validator.ValidateClient(r.Context(), req)
	if err != nil {
		h.logger.Error("validate client failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, err.Error()))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Health handles GET /health.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
