package http

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

// NewRouter sets up the HTTP routes and applies the middleware chain.
func NewRouter(h *Handler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /clients", h.CreateClient)
	mux.HandleFunc("GET /clients", h.ListClients)
	// /clients/validate must be registered before /clients/{id} to avoid ambiguity.
	mux.HandleFunc("POST /clients/validate", h.ValidateClient)
	mux.HandleFunc("GET /clients/{id}", h.GetClient)
	mux.HandleFunc("DELETE /clients/{id}", h.DeleteClient)
	mux.HandleFunc("GET /health", h.Health)

	// Apply middleware chain (Chain of Responsibility pattern).
	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
