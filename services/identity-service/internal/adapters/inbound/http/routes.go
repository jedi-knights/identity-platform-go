package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/httpmw"

	_ "github.com/ocrosby/identity-platform-go/services/identity-service/docs"
)

// NewRouter sets up the HTTP routes and applies the middleware chain.
func NewRouter(h *Handler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/login", h.Login)
	mux.HandleFunc("POST /auth/register", h.Register)
	mux.HandleFunc("POST /auth/request-verification", h.RequestVerification)
	mux.HandleFunc("POST /auth/verify-email", h.VerifyEmail)
	mux.HandleFunc("GET /users/{id}/claims", h.GetUserClaims)
	mux.HandleFunc("GET /users/{id}/active-account", h.GetActiveAccount)
	mux.HandleFunc("PUT /users/{id}/active-account", h.SetActiveAccount)
	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Stack applies RequestID → TraceID → Recovery → Logging, outermost first,
	// so every log line carries the request and trace IDs.
	return httpmw.Stack(logger)(mux)
}
