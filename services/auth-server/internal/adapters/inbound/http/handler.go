package http

import (
	"context"
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

	grantType := domain.GrantType(r.FormValue("grant_type"))
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scopeStr := r.FormValue("scope")

	var scopes []string
	if scopeStr != "" {
		scopes = strings.Split(scopeStr, " ")
	}

	req := domain.GrantRequest{
		GrantType:    grantType,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Code:         r.FormValue("code"),
		CodeVerifier: r.FormValue("code_verifier"),
		RedirectURI:  r.FormValue("redirect_uri"),
	}

	resp, err := h.issuer.IssueToken(r.Context(), req)
	if err != nil {
		h.logger.Error("token issuance failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, err.Error()))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
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
// @Success      200  {object}  application.IntrospectResponse
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

// tokenIntrospectorAdapter adapts TokenService to the TokenIntrospector port.
type tokenIntrospectorAdapter struct {
	svc *application.TokenService
}

func NewTokenIntrospectorAdapter(svc *application.TokenService) ports.TokenIntrospector {
	return &tokenIntrospectorAdapter{svc: svc}
}

func (a *tokenIntrospectorAdapter) Introspect(ctx context.Context, raw string) (*application.IntrospectResponse, error) {
	return a.svc.Introspect(ctx, raw)
}

// tokenRevokerAdapter adapts TokenService to the TokenRevoker port.
type tokenRevokerAdapter struct {
	svc *application.TokenService
}

func NewTokenRevokerAdapter(svc *application.TokenService) ports.TokenRevoker {
	return &tokenRevokerAdapter{svc: svc}
}

func (a *tokenRevokerAdapter) Revoke(ctx context.Context, raw string) error {
	return a.svc.Revoke(ctx, raw)
}
