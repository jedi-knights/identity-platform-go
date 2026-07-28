// Package http holds the entitlements-service inbound HTTP adapter.
// Handlers translate wire-level requests into application-level calls
// and back — they do not embed business rules; those live in the
// application package.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
)

// Handler wraps the entitlements-service application layer and exposes
// it over HTTP. Constructed once at composition-root startup; safe for
// concurrent use.
type Handler struct {
	accounts *application.AccountService
	logger   logging.Logger
}

// NewHandler wires an application service into the HTTP adapter.
// accounts must be non-nil.
func NewHandler(accounts *application.AccountService, logger logging.Logger) *Handler {
	if accounts == nil {
		panic("http: NewHandler called with nil accounts service")
	}
	if logger == nil {
		panic("http: NewHandler called with nil logger")
	}
	return &Handler{accounts: accounts, logger: logger}
}

// createPersonalAccountRequest is the wire-level shape POSTed to
// /accounts/personal. Matches the outbound port shape identity-service
// (E7-S1c) will use, so the two evolve together.
type createPersonalAccountRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type createPersonalAccountResponse struct {
	AccountID    string `json:"account_id"`
	BillingEmail string `json:"billing_email"`
	UserID       string `json:"user_id"`
	Created      bool   `json:"created"` // true = we just created it, false = already existed
}

// CreatePersonalAccount handles POST /accounts/personal.
//
// Status codes:
//   - 201 Created when a new account is created
//   - 200 OK     when an existing account is returned (idempotent replay)
//   - 400 Bad Request on malformed body or missing required fields
//   - 500 Internal Server Error on any other failure
//
// Distinct 201/200 lets identity-service tell "created" from "already
// existed" without a parallel probe — useful for the register-flow
// audit event, which should not double-count new signups.
func (h *Handler) CreatePersonalAccount(w http.ResponseWriter, r *http.Request) {
	var req createPersonalAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	acc, created, err := h.accounts.CreatePersonalAccount(r.Context(), req.UserID, req.Email)
	if err != nil {
		writeAppError(w, h.logger, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, createPersonalAccountResponse{
		AccountID:    acc.ID,
		BillingEmail: acc.BillingEmail,
		UserID:       acc.UserID,
		Created:      created,
	})
}

// Health handles GET /health.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// writeJSON serialises v as JSON and writes it with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a stable {error, message} shape at the given status.
func writeError(w http.ResponseWriter, logger logging.Logger, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg}); err != nil {
		logger.Error("encoding error response", "err", err.Error())
	}
}

// writeAppError maps an apperrors.AppError to the appropriate HTTP status.
// Unknown errors fall through to 500 with the message hidden from the
// client (server-side log carries the detail).
func writeAppError(w http.ResponseWriter, logger logging.Logger, err error) {
	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		logger.Error("unexpected error from application layer", "err", err.Error())
		writeError(w, logger, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	switch appErr.Code() {
	case apperrors.ErrCodeBadRequest:
		writeError(w, logger, http.StatusBadRequest, "invalid_request", appErr.Message())
	case apperrors.ErrCodeNotFound:
		writeError(w, logger, http.StatusNotFound, "not_found", appErr.Message())
	case apperrors.ErrCodeConflict:
		writeError(w, logger, http.StatusConflict, "conflict", appErr.Message())
	default:
		logger.Error("unmapped app error code", "code", appErr.Code(), "err", appErr.Error())
		writeError(w, logger, http.StatusInternalServerError, "server_error", "internal error")
	}
}
