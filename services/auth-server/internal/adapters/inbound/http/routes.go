package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/httputil"

	_ "github.com/ocrosby/identity-platform-go/services/auth-server/docs"
)

// NewRouter sets up the HTTP routes and applies the middleware chain.
// jwks may be nil — when nil, the /.well-known/jwks.json route is not
// registered (HS256 mode does not publish a JWKS document). userInfo may
// be nil — when nil, /userinfo is not registered (OIDC mode disabled when
// AUTH_JWT_OIDC_ISSUER is unset).
//
// metadata may be nil — when nil, the RFC 8414 / OIDC Discovery
// endpoints are not registered (ADR-0012 requires the operator to set
// AUTH_METADATA_PUBLIC_BASE_URL so the metadata document can carry
// absolute URLs).
func NewRouter(h *Handler, jwks *JWKSHandler, userInfo *UserInfoHandler, metadata *MetadataHandler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /oauth/token", h.Token)
	mux.HandleFunc("GET /oauth/authorize", h.Authorize)
	// /oauth/par is RFC 9126 (ADR-0021); the handler itself returns 501
	// when the authorize subsystem (AuthorizeConfig) is not configured,
	// mirroring /oauth/authorize's own nil-config behavior.
	mux.HandleFunc("POST /oauth/par", h.PushAuthorize)
	mux.HandleFunc("POST /oauth/introspect", h.Introspect)
	mux.HandleFunc("POST /oauth/revoke", h.Revoke)
	// /internal/issue-code is service-only; the handler itself returns 404
	// when the operator has not configured a service bearer token.
	mux.HandleFunc("POST /internal/issue-code", h.IssueCode)
	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))
	if jwks != nil {
		// RFC 7517 §4.1: JWKS lives at /.well-known/jwks.json by convention.
		mux.HandleFunc("GET /.well-known/jwks.json", jwks.Get)
	}
	if userInfo != nil {
		// OIDC §5.3.1: both GET and POST are accepted.
		mux.HandleFunc("GET /userinfo", userInfo.Get)
		mux.HandleFunc("POST /userinfo", userInfo.Get)
	}
	if metadata != nil {
		// RFC 8414 §3 — OAuth 2.0 Authorization Server Metadata.
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", metadata.OAuthMetadata)
		// OIDC Discovery 1.0 §4. Registered alongside the RFC 8414
		// endpoint; the builder produces an OIDC-flavoured document
		// only when OIDC mode is active.
		mux.HandleFunc("GET /.well-known/openid-configuration", metadata.OIDCMetadata)
	}

	// Apply middleware chain (Chain of Responsibility pattern).
	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
