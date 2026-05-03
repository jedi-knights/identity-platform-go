package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	_ "github.com/ocrosby/identity-platform-go/services/example-resource-service/docs"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// NewRouter sets up HTTP routes with auth and scope middleware (Chain of Responsibility).
//
// When introspector is non-nil, IntrospectionAuthMiddleware is used — tokens are
// validated remotely and revocation is honoured. When nil, JWTAuthMiddleware is used
// as a fallback for local dev without the full stack running.
//
// audience is passed to JWTAuthMiddleware for local validation. When empty, audience
// validation is skipped. Ignored when introspector is non-nil.
func NewRouter(h *Handler, logger logging.Logger, signingKey []byte, audience string, introspector ports.TokenIntrospector) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Select the auth middleware based on whether token-introspection-service is configured.
	var authMiddleware func(http.Handler) http.Handler
	if introspector != nil {
		authMiddleware = IntrospectionAuthMiddleware(introspector, logger)
	} else {
		authMiddleware = JWTAuthMiddleware(signingKey, audience, logger)
	}

	mux.Handle("GET /resources", authMiddleware(
		RequireScopeMiddleware("read")(http.HandlerFunc(h.ListResources)),
	))
	mux.Handle("GET /resources/{id}", authMiddleware(
		RequireScopeMiddleware("read")(http.HandlerFunc(h.GetResource)),
	))
	mux.Handle("POST /resources", authMiddleware(
		RequireScopeMiddleware("write")(http.HandlerFunc(h.CreateResource)),
	))

	// TraceIDMiddleware must be outermost so trace IDs are in context when
	// LoggingMiddleware reads them (it captures ctx before calling next).
	return httputil.TraceIDMiddleware(
		httputil.RecoveryMiddleware(logger)(
			httputil.LoggingMiddleware(logger)(mux),
		),
	)
}
