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
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "authorization endpoint - not yet implemented",
	})
}

// Introspect handles POST /oauth/introspect.
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
