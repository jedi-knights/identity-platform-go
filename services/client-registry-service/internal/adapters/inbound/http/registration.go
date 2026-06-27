package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/ports"
)

// RegistrationHandler serves the RFC 7591 dynamic client registration
// endpoint. It is split from [Handler] because the request / response
// shapes and the error vocabulary differ — RFC 7591 owns its own
// codes and they do not pass through apperrors.
type RegistrationHandler struct {
	registrar ports.ClientRegistrar
	logger    logging.Logger
}

// NewRegistrationHandler wires the RFC 7591 handler around the
// registrar port. A nil registrar panics — composition errors are loud
// at startup.
func NewRegistrationHandler(registrar ports.ClientRegistrar, logger logging.Logger) *RegistrationHandler {
	if registrar == nil {
		panic("http: NewRegistrationHandler called with nil registrar")
	}
	return &RegistrationHandler{registrar: registrar, logger: logger}
}

// Register handles POST /register per RFC 7591 §3.
//
// @Summary      RFC 7591 Dynamic Client Registration
// @Description  Registers a new OAuth client. The response carries the issued credentials plus a registration access token for use with the RFC 7592 management endpoints.
// @Tags         registration
// @Accept       json
// @Produce      json
// @Param        request  body      domain.RegistrationRequest   true  "Client metadata"
// @Success      201      {object}  domain.RegistrationResponse
// @Failure      400      {object}  domain.RegistrationError
// @Failure      413      {string}  string  "request body too large"
// @Failure      500      {object}  domain.RegistrationError
// @Router       /register [post]
func (h *RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeRegistrationError(w, &domain.RegistrationError{
			Code:        domain.RegistrationErrorInvalidClientMetadata,
			Description: "invalid request body",
		}, http.StatusBadRequest)
		return
	}

	resp, err := h.registrar.Register(r.Context(), req)
	if err != nil {
		var regErr *domain.RegistrationError
		if errors.As(err, &regErr) {
			writeRegistrationError(w, regErr, http.StatusBadRequest)
			return
		}
		if h.logger != nil {
			h.logger.Error("dynamic client registration failed", "err", err)
		}
		writeRegistrationError(w, &domain.RegistrationError{
			Code:        domain.RegistrationErrorServerError,
			Description: "internal error",
		}, http.StatusInternalServerError)
		return
	}

	writeJSONNoStore(w, http.StatusCreated, resp)
}

// writeRegistrationError emits the RFC 7591 §3.2.2 error envelope with
// the cache headers the spec mandates.
func writeRegistrationError(w http.ResponseWriter, err *domain.RegistrationError, status int) {
	writeJSONNoStore(w, status, err)
}

// writeJSONNoStore matches the cache-control posture RFC 7591 §3.2.1
// requires of the response body: this resource carries credentials and
// must never be cached.
func writeJSONNoStore(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
