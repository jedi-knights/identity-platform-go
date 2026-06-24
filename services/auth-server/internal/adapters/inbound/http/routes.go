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
// registered (HS256 mode does not publish a JWKS document).
func NewRouter(h *Handler, jwks *JWKSHandler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /oauth/token", h.Token)
	mux.HandleFunc("GET /oauth/authorize", h.Authorize)
	mux.HandleFunc("POST /oauth/introspect", h.Introspect)
	mux.HandleFunc("POST /oauth/revoke", h.Revoke)
	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))
	if jwks != nil {
		// RFC 7517 §4.1: JWKS lives at /.well-known/jwks.json by convention.
		mux.HandleFunc("GET /.well-known/jwks.json", jwks.Get)
	}

	// Apply middleware chain (Chain of Responsibility pattern).
	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
