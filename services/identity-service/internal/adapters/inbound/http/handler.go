package http

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/ports"
)

// Handler holds all HTTP handler dependencies.
type Handler struct {
	authenticator ports.Authenticator
	registrar     ports.UserRegistrar
	logger        logging.Logger
}

func NewHandler(authenticator ports.Authenticator, registrar ports.UserRegistrar, logger logging.Logger) *Handler {
	return &Handler{
		authenticator: authenticator,
		registrar:     registrar,
		logger:        logger,
	}
}

// Login handles POST /auth/login.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req application.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.authenticator.Login(r.Context(), req)
	if err != nil {
		h.logger.Error("login failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, err.Error()))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Register handles POST /auth/register.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req application.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.registrar.Register(r.Context(), req)
	if err != nil {
		h.logger.Error("registration failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, err.Error()))
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// Health handles GET /health.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
