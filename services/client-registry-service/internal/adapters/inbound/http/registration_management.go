package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/ports"
)

// RegistrationManagementHandler serves the RFC 7592 management
// endpoints (GET/PUT/DELETE /register/{client_id}). Authentication is
// the registration_access_token returned by RFC 7591 Register — the
// handler extracts it from Authorization and forwards to the
// application layer, which performs the bcrypt comparison.
type RegistrationManagementHandler struct {
	mgmt   ports.ClientRegistrationManager
	logger logging.Logger
}

// NewRegistrationManagementHandler wires the handler. A nil manager
// panics — composition errors are loud at startup.
func NewRegistrationManagementHandler(mgmt ports.ClientRegistrationManager, logger logging.Logger) *RegistrationManagementHandler {
	if mgmt == nil {
		panic("http: NewRegistrationManagementHandler called with nil manager")
	}
	return &RegistrationManagementHandler{mgmt: mgmt, logger: logger}
}

// Get serves GET /register/{client_id} per RFC 7592 §2.1.
//
// @Summary      RFC 7592 read registration
// @Tags         registration
// @Produce      json
// @Param        client_id  path      string  true  "Client ID"
// @Success      200        {object}  domain.RegistrationResponse
// @Failure      401        {object}  domain.RegistrationError
// @Failure      404        {object}  domain.RegistrationError
// @Router       /register/{client_id} [get]
func (h *RegistrationManagementHandler) Get(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	token := extractBearer(r)
	resp, err := h.mgmt.ReadRegistration(r.Context(), clientID, token)
	if err != nil {
		h.writeManagementError(w, err)
		return
	}
	writeJSONNoStore(w, http.StatusOK, resp)
}

// Put serves PUT /register/{client_id} per RFC 7592 §2.2.
//
// @Summary      RFC 7592 update registration
// @Tags         registration
// @Accept       json
// @Produce      json
// @Param        client_id  path      string                       true  "Client ID"
// @Param        request    body      domain.RegistrationRequest   true  "Replacement metadata"
// @Success      200        {object}  domain.RegistrationResponse
// @Failure      400        {object}  domain.RegistrationError
// @Failure      401        {object}  domain.RegistrationError
// @Failure      404        {object}  domain.RegistrationError
// @Router       /register/{client_id} [put]
func (h *RegistrationManagementHandler) Put(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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

	clientID := r.PathValue("client_id")
	token := extractBearer(r)
	resp, err := h.mgmt.UpdateRegistration(r.Context(), clientID, token, req)
	if err != nil {
		h.writeManagementError(w, err)
		return
	}
	writeJSONNoStore(w, http.StatusOK, resp)
}

// Delete serves DELETE /register/{client_id} per RFC 7592 §2.3.
//
// @Summary      RFC 7592 deregister
// @Tags         registration
// @Param        client_id  path  string  true  "Client ID"
// @Success      204
// @Failure      401        {object}  domain.RegistrationError
// @Failure      404        {object}  domain.RegistrationError
// @Router       /register/{client_id} [delete]
func (h *RegistrationManagementHandler) Delete(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	token := extractBearer(r)
	if err := h.mgmt.DeleteRegistration(r.Context(), clientID, token); err != nil {
		h.writeManagementError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// writeManagementError maps a typed RegistrationError to the right
// status code and emits the RFC 7591 / 7592 error envelope. Untyped
// errors are logged and surfaced as 500 server_error.
func (h *RegistrationManagementHandler) writeManagementError(w http.ResponseWriter, err error) {
	var regErr *domain.RegistrationError
	if !errors.As(err, &regErr) {
		if h.logger != nil {
			h.logger.Error("registration management error", "err", err)
		}
		writeRegistrationError(w, &domain.RegistrationError{
			Code:        domain.RegistrationErrorServerError,
			Description: "internal error",
		}, http.StatusInternalServerError)
		return
	}
	switch regErr.Code {
	case domain.RegistrationErrorInvalidToken:
		writeRegistrationError(w, regErr, http.StatusUnauthorized)
	case "not_found":
		writeRegistrationError(w, regErr, http.StatusNotFound)
	default:
		writeRegistrationError(w, regErr, http.StatusBadRequest)
	}
}

// extractBearer parses the Authorization header and returns the bearer
// token (without the "Bearer " prefix). Returns "" when the header is
// absent or malformed — the application layer treats empty as a missing
// credential.
func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}
