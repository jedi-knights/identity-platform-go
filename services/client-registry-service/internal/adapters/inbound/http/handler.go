package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
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

// decodeBody decodes a JSON request body into dst. It returns an error
// response and true if the caller should return immediately. The 1 MB limit
// must already be applied via http.MaxBytesReader before calling this helper.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) (stop bool) {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return true
		}
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return true
	}
	return false
}

// CreateClient handles POST /clients.
//
// @Summary      Register a new OAuth client
// @Description  Creates a new OAuth2 client with generated credentials
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        request  body      domain.CreateClientRequest   true  "Client registration data"
// @Success      201      {object}  domain.CreateClientResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      413      {object}  httputil.ErrorResponse
// @Failure      500      {object}  httputil.ErrorResponse
// @Router       /clients [post]
func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.CreateClientRequest
	if decodeBody(w, r, &req) {
		return
	}

	resp, err := h.creator.CreateClient(r.Context(), req)
	if err != nil {
		var ae *apperrors.AppError
		if errors.As(err, &ae) {
			httputil.WriteError(w, ae)
			return
		}
		h.logger.Error("create client failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to create client"))
		return
	}

	w.Header().Set("Location", "/clients/"+url.PathEscape(resp.ClientID))
	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// ListClients handles GET /clients.
//
// @Summary      List all registered clients
// @Description  Returns all registered OAuth2 clients (secrets excluded)
// @Tags         clients
// @Produce      json
// @Success      200  {array}   domain.GetClientResponse
// @Failure      500  {object}  httputil.ErrorResponse
// @Router       /clients [get]
func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	resp, err := h.reader.ListClients(r.Context())
	if err != nil {
		h.logger.Error("list clients failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to list clients"))
		return
	}

	// Coerce nil to an empty slice so the response body is always [] not null.
	if resp == nil {
		resp = []*domain.GetClientResponse{}
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
// @Success      200  {object}  domain.GetClientResponse
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
		var ae *apperrors.AppError
		if errors.As(err, &ae) {
			httputil.WriteError(w, ae)
			return
		}
		h.logger.Error("get client failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to get client"))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// DeleteClient handles DELETE /clients/{id}.
//
// @Summary      Delete a client
// @Description  Deletes an OAuth2 client by ID. Idempotent: deleting an absent client returns 204.
// @Tags         clients
// @Produce      json
// @Param        id   path      string  true  "Client ID"
// @Success      204  "Client deleted"
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /clients/{id} [delete]
func (h *Handler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "client id is required"))
		return
	}

	if err := h.deleter.DeleteClient(r.Context(), id); err != nil {
		var ae *apperrors.AppError
		if errors.As(err, &ae) {
			// DELETE is idempotent — a direct not-found AppError means the resource
			// is already absent, which is the desired state. Deeper not-found errors
			// wrapped inside infrastructure errors are not treated as idempotent success
			// because the outer error may indicate a real infrastructure problem.
			if ae.Code() == apperrors.ErrCodeNotFound {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			httputil.WriteError(w, ae)
			return
		}
		h.logger.Error("delete client failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to delete client"))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ValidateClient handles POST /clients/validate.
//
// @Summary      Validate client credentials
// @Description  Returns 200 when credentials are valid. Returns 401 when credentials are rejected.
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        request  body      domain.ValidateClientRequest   true  "Client credentials"
// @Success      200      {object}  domain.ValidateClientResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      401      {object}  httputil.ErrorResponse
// @Failure      413      {object}  httputil.ErrorResponse
// @Failure      500      {object}  httputil.ErrorResponse
// @Router       /clients/validate [post]
func (h *Handler) ValidateClient(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.ValidateClientRequest
	if decodeBody(w, r, &req) {
		return
	}

	// Validate required fields here in addition to the service layer so the HTTP
	// handler returns a 400 with a descriptive message rather than a 200 with
	// Valid=false, which would be ambiguous for callers.
	if req.ClientID == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "client_id is required"))
		return
	}
	if req.ClientSecret == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "client_secret is required"))
		return
	}

	resp, err := h.validator.ValidateClient(r.Context(), req)
	if err != nil {
		var ae *apperrors.AppError
		if errors.As(err, &ae) {
			httputil.WriteError(w, ae)
			return
		}
		h.logger.Error("validate client failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to validate client"))
		return
	}

	// Return 401 for invalid credentials rather than 200 with valid=false.
	// Hiding auth failures in a success response violates REST conventions
	// and forces callers to inspect the body to distinguish success from failure.
	if !resp.Valid {
		w.Header().Set("WWW-Authenticate", `Basic realm="client-registry"`)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid client credentials"))
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
