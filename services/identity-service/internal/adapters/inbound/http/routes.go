package http

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// NewRouter sets up the HTTP routes and applies the middleware chain.
func NewRouter(h *Handler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/login", h.Login)
	mux.HandleFunc("POST /auth/register", h.Register)
	mux.HandleFunc("GET /health", h.Health)

	// Apply middleware chain (Chain of Responsibility pattern).
	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
