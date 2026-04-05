package http

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Handler holds all HTTP handler dependencies.
type Handler struct {
	issuer       ports.TokenIssuer
	introspector ports.TokenIntrospector
	revoker      ports.TokenRevoker
	logger       logging.Logger
}

func NewHandler(
	issuer ports.TokenIssuer,
	introspector ports.TokenIntrospector,
	revoker ports.TokenRevoker,
	logger logging.Logger,
) *Handler {
	return &Handler{
		issuer:       issuer,
		introspector: introspector,
		revoker:      revoker,
		logger:       logger,
	}
}

// writeOAuthError writes an RFC 6749-compliant JSON error response.
func writeOAuthError(w http.ResponseWriter, code string, description string, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(httpStatus)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	}); err != nil {
		slog.Error("failed to encode oauth error", "error", err)
	}
}

// Token handles POST /oauth/token.
//
// @Summary      Issue access token
// @Description  Issues an OAuth2 access token using the specified grant type (RFC 6749)
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        grant_type    formData  string  true  "OAuth2 grant type"
// @Param        client_id     formData  string  true  "Client identifier"
// @Param        client_secret formData  string  true  "Client secret"
// @Param        scope         formData  string  false "Space-delimited list of scopes"
// @Param        code          formData  string  false "Authorization code"
// @Param        code_verifier formData  string  false "PKCE code verifier"
// @Param        redirect_uri  formData  string  false "Redirect URI"
// @Success      200  {object}  domain.GrantResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /oauth/token [post]
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid form data"))
		return
	}

	req, ok := parseGrantRequest(w, r)
	if !ok {
		return
	}

	resp, err := h.issuer.IssueToken(r.Context(), req)
	if err != nil {
		h.logger.Error("token issuance failed", "error", err.Error())
		writeTokenError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// parseGrantRequest extracts and validates the OAuth2 token request fields from the form.
// It writes an error response and returns false if any required field is missing.
func parseGrantRequest(w http.ResponseWriter, r *http.Request) (domain.GrantRequest, bool) {
	grantType := domain.GrantType(r.FormValue("grant_type"))
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if grantType == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "grant_type is required"))
		return domain.GrantRequest{}, false
	}
	if clientID == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "client_id is required"))
		return domain.GrantRequest{}, false
	}
	if clientSecret == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "client_secret is required"))
		return domain.GrantRequest{}, false
	}

	var scopes []string
	if scopeStr := r.FormValue("scope"); scopeStr != "" {
		scopes = strings.Split(scopeStr, " ")
	}

	return domain.GrantRequest{
		GrantType:    grantType,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Code:         r.FormValue("code"),
		CodeVerifier: r.FormValue("code_verifier"),
		RedirectURI:  r.FormValue("redirect_uri"),
	}, true
}

// writeTokenError maps an application error to an RFC 6749-compliant OAuth2 error response.
func writeTokenError(w http.ResponseWriter, err error) {
	if apperrors.HTTPStatus(err) >= 500 {
		writeOAuthError(w, "server_error", "an internal error occurred", http.StatusInternalServerError)
		return
	}
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "client not found") || strings.Contains(errMsg, "invalid client credentials"):
		writeOAuthError(w, "invalid_client", "client authentication failed", http.StatusUnauthorized)
	case strings.Contains(errMsg, "scope not allowed"):
		writeOAuthError(w, "invalid_scope", "the requested scope is invalid", http.StatusBadRequest)
	case strings.Contains(errMsg, "grant type not allowed") || strings.Contains(errMsg, "unsupported grant type"):
		writeOAuthError(w, "unsupported_grant_type", "grant type not supported", http.StatusBadRequest)
	default:
		writeOAuthError(w, "invalid_request", "the request is invalid", http.StatusBadRequest)
	}
}

// Authorize handles GET /oauth/authorize (stub).
//
// @Summary      Authorization endpoint
// @Description  Authorization endpoint - not yet implemented
// @Tags         oauth
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /oauth/authorize [get]
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "authorization endpoint - not yet implemented",
	})
}

// Introspect handles POST /oauth/introspect.
//
// @Summary      Introspect token
// @Description  Validates and returns metadata for a token per RFC 7662
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token  formData  string  true  "Token to introspect"
// @Success      200  {object}  domain.IntrospectResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Failure      500  {object}  httputil.ErrorResponse
// @Router       /oauth/introspect [post]
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid form data"))
		return
	}

	token := r.FormValue("token")
	if token == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "token is required"))
		return
	}

	resp, err := h.introspector.Introspect(r.Context(), token)
	if err != nil {
		h.logger.Error("introspection failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "introspection failed"))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Revoke handles POST /oauth/revoke.
//
// @Summary      Revoke token
// @Description  Revokes a token per RFC 7009
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token  formData  string  true  "Token to revoke"
// @Success      200  "Token revoked"
// @Failure      400  {object}  httputil.ErrorResponse
// @Router       /oauth/revoke [post]
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid form data"))
		return
	}

	token := r.FormValue("token")
	if token == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "token is required"))
		return
	}

	if err := h.revoker.Revoke(r.Context(), token); err != nil {
		h.logger.Error("revocation failed", "error", err.Error())
		// Per RFC 7009, return 200 even if token not found.
	}

	w.WriteHeader(http.StatusOK)
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

// tokenIssuerAdapter adapts the grant registry to the TokenIssuer port.
type tokenIssuerAdapter struct {
	registry *application.GrantStrategyRegistry
}

func NewTokenIssuerAdapter(registry *application.GrantStrategyRegistry) ports.TokenIssuer {
	return &tokenIssuerAdapter{registry: registry}
}

func (a *tokenIssuerAdapter) IssueToken(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	return a.registry.Handle(ctx, req)
}

// introspectorSvc is the narrow interface required by tokenIntrospectorAdapter.
// Defining it here (at the adapter boundary) keeps the adapter decoupled from
// the concrete application.TokenService type.
type introspectorSvc interface {
	Introspect(ctx context.Context, raw string) (*domain.IntrospectResponse, error)
}

// revokerSvc is the narrow interface required by tokenRevokerAdapter.
type revokerSvc interface {
	Revoke(ctx context.Context, raw string) error
}

// tokenIntrospectorAdapter adapts any introspectorSvc to the TokenIntrospector port.
type tokenIntrospectorAdapter struct {
	svc introspectorSvc
}

func NewTokenIntrospectorAdapter(svc introspectorSvc) ports.TokenIntrospector {
	return &tokenIntrospectorAdapter{svc: svc}
}

func (a *tokenIntrospectorAdapter) Introspect(ctx context.Context, raw string) (*domain.IntrospectResponse, error) {
	return a.svc.Introspect(ctx, raw)
}

// tokenRevokerAdapter adapts any revokerSvc to the TokenRevoker port.
type tokenRevokerAdapter struct {
	svc revokerSvc
}

func NewTokenRevokerAdapter(svc revokerSvc) ports.TokenRevoker {
	return &tokenRevokerAdapter{svc: svc}
}

func (a *tokenRevokerAdapter) Revoke(ctx context.Context, raw string) error {
	return a.svc.Revoke(ctx, raw)
}
