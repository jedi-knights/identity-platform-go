package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/httputil"

	_ "github.com/ocrosby/identity-platform-go/services/client-registry-service/docs"
)

// NewRouter sets up the HTTP routes and applies the middleware chain.
// registration may be nil — when nil, the RFC 7591 /register endpoint is
// not registered (used in tests that exercise only the admin /clients
// surface).
func NewRouter(h *Handler, registration *RegistrationHandler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /clients", h.CreateClient)
	mux.HandleFunc("GET /clients", h.ListClients)
	// /clients/validate must be registered before /clients/{id} to avoid ambiguity.
	mux.HandleFunc("POST /clients/validate", h.ValidateClient)
	mux.HandleFunc("GET /clients/{id}", h.GetClient)
	mux.HandleFunc("DELETE /clients/{id}", h.DeleteClient)
	if registration != nil {
		// RFC 7591 §3 — Dynamic Client Registration.
		mux.HandleFunc("POST /register", registration.Register)
	}
	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Apply middleware chain (Chain of Responsibility pattern).
	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
