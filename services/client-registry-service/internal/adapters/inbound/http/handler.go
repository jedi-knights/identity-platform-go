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
//
// @Summary      Register a new OAuth client
// @Description  Creates a new OAuth2 client with generated credentials
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        request  body      application.CreateClientRequest   true  "Client registration data"
// @Success      201      {object}  application.CreateClientResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      500      {object}  httputil.ErrorResponse
// @Router       /clients [post]
func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
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
//
// @Summary      List all registered clients
// @Description  Returns all registered OAuth2 clients (secrets excluded)
// @Tags         clients
// @Produce      json
// @Success      200  {array}   application.GetClientResponse
// @Failure      500  {object}  httputil.ErrorResponse
// @Router       /clients [get]
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
//
// @Summary      Get a specific client
// @Description  Returns details for a specific OAuth2 client by ID
// @Tags         clients
// @Produce      json
// @Param        id   path      string  true  "Client ID"
// @Success      200  {object}  application.GetClientResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Failure      404  {object}  httputil.ErrorResponse
// @Router       /clients/{id} [get]
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
//
// @Summary      Delete a client
// @Description  Deletes an OAuth2 client by ID
// @Tags         clients
// @Produce      json
// @Param        id   path      string  true  "Client ID"
// @Success      204  "Client deleted"
// @Failure      400  {object}  httputil.ErrorResponse
// @Failure      404  {object}  httputil.ErrorResponse
// @Router       /clients/{id} [delete]
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
//
// @Summary      Validate client credentials
// @Description  Checks whether the provided client ID and secret are valid
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        request  body      application.ValidateClientRequest   true  "Client credentials"
// @Success      200      {object}  application.ValidateClientResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      500      {object}  httputil.ErrorResponse
// @Router       /clients/validate [post]
func (h *Handler) ValidateClient(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
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
//
// @Summary      Health check
// @Description  Returns service health status
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
