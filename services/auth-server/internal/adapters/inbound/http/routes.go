package http

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// NewRouter sets up the HTTP routes and applies the middleware chain.
func NewRouter(h *Handler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /oauth/token", h.Token)
	mux.HandleFunc("GET /oauth/authorize", h.Authorize)
	mux.HandleFunc("POST /oauth/introspect", h.Introspect)
	mux.HandleFunc("POST /oauth/revoke", h.Revoke)
	mux.HandleFunc("GET /health", h.Health)

	// Apply middleware chain (Chain of Responsibility pattern).
	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
