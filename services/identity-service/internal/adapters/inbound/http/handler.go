package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/ports"
)

// Handler holds all HTTP handler dependencies.
type Handler struct {
	authenticator ports.Authenticator
	registrar     ports.UserRegistrar
	verifier      ports.EmailVerifier
	logger        logging.Logger
}

func NewHandler(
	authenticator ports.Authenticator,
	registrar ports.UserRegistrar,
	verifier ports.EmailVerifier,
	logger logging.Logger,
) *Handler {
	return &Handler{
		authenticator: authenticator,
		registrar:     registrar,
		verifier:      verifier,
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
		var ae *apperrors.AppError
		if !errors.As(err, &ae) || ae.Code() == apperrors.ErrCodeInternal {
			h.logger.Error("login failed", "error", err.Error())
		}
		httputil.WriteError(w, err)
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
		var ae *apperrors.AppError
		if !errors.As(err, &ae) || ae.Code() == apperrors.ErrCodeInternal {
			h.logger.Error("registration failed", "error", err.Error())
		}
		httputil.WriteError(w, err)
		return
	}

	w.Header().Set("Location", "/users/"+resp.UserID)
	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// RequestVerification handles POST /auth/request-verification.
//
// The response is intentionally 204 No Content regardless of whether the
// email is registered — surfacing "no such user" here would let an
// attacker enumerate valid emails.
//
// @Summary      Request a verification email
// @Description  Sends a verification email to the address on the request. Always returns 204 to prevent user enumeration.
// @Tags         auth
// @Accept       json
// @Param        request  body  domain.RequestVerificationRequest  true  "Email"
// @Success      204
// @Failure      400      {object}  httputil.ErrorResponse
// @Router       /auth/request-verification [post]
func (h *Handler) RequestVerification(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.RequestVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	if err := h.verifier.RequestVerification(r.Context(), req); err != nil {
		var ae *apperrors.AppError
		if errors.As(err, &ae) && ae.Code() == apperrors.ErrCodeBadRequest {
			httputil.WriteError(w, err)
			return
		}
		// Anything else (infra errors) is logged but does not leak — return 204
		// to keep responses indistinguishable.
		h.logger.Error("request verification failed", "error", err.Error())
	}

	w.WriteHeader(http.StatusNoContent)
}

// VerifyEmail handles POST /auth/verify-email.
//
// @Summary      Verify an email address
// @Description  Redeems a one-time verification token and marks the user verified.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      domain.VerifyEmailRequest   true  "Verification token"
// @Success      200      {object}  domain.VerifyEmailResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      401      {object}  httputil.ErrorResponse
// @Router       /auth/verify-email [post]
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.verifier.VerifyEmail(r.Context(), req)
	if err != nil {
		var ae *apperrors.AppError
		if !errors.As(err, &ae) || ae.Code() == apperrors.ErrCodeInternal {
			h.logger.Error("email verification failed", "error", err.Error())
		}
		httputil.WriteError(w, err)
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
