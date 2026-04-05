package http

import (
	"encoding/json"
	"net/http"
	"strings"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
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
//
// @Summary      Authenticate user
// @Description  Authenticates a user with email and password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      domain.LoginRequest   true  "Login credentials"
// @Success      200      {object}  domain.LoginResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      401      {object}  httputil.ErrorResponse
// @Router       /auth/login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.authenticator.Login(r.Context(), req)
	if err != nil {
		h.logger.Error("login failed", "error", err.Error())
		if strings.Contains(err.Error(), "required") {
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, err.Error()))
			return
		}
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid credentials"))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Register handles POST /auth/register.
//
// @Summary      Register new user
// @Description  Registers a new user with email, password, and name
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      domain.RegisterRequest   true  "Registration data"
// @Success      201      {object}  domain.RegisterResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Router       /auth/register [post]
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.registrar.Register(r.Context(), req)
	if err != nil {
		h.logger.Error("registration failed", "error", err.Error())
		if strings.Contains(err.Error(), "already registered") {
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeConflict, "email already registered"))
			return
		}
		if strings.Contains(err.Error(), "required") {
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, err.Error()))
			return
		}
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "registration failed"))
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, resp)
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
