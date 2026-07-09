package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/httputil"
	"github.com/jedi-knights/go-platform/jwtutil"

	_ "github.com/ocrosby/identity-platform-go/services/example-resource-service/docs"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// NewRouter sets up HTTP routes with auth and scope middleware (Chain of Responsibility).
//
// Auth middleware selection (in priority order):
//  1. introspector != nil       → IntrospectionAuthMiddleware (handles revocation)
//  2. keySource != nil          → RS256AuthMiddleware (local RS256 + JWKS)
//  3. otherwise                 → JWTAuthMiddleware (legacy HS256 with shared secret)
//
// audience is used for token audience validation (RFC 9068 §2.2). issuer is
// used for issuer validation in the local paths only (RFC 8725 §3.8).
// Empty strings disable the respective validation.
func NewRouter(h *Handler, logger logging.Logger, signingKey []byte, keySource jwtutil.KeySource, audience, issuer string, introspector ports.TokenIntrospector) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Select the auth middleware. Introspection wins because it is the only
	// path that honours revocation; JWKS next for asymmetric local validation;
	// HS256 last for legacy / standalone-dev mode.
	var authMiddleware func(http.Handler) http.Handler
	switch {
	case introspector != nil:
		authMiddleware = IntrospectionAuthMiddleware(introspector, logger, audience)
	case keySource != nil:
		authMiddleware = RS256AuthMiddleware(keySource, audience, issuer, logger)
	default:
		authMiddleware = JWTAuthMiddleware(signingKey, audience, issuer, logger)
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

	// GET /resources/sensitive demonstrates RFC 9470 step-up authentication
	// (ADR-0024 in identity-platform-go's auth-server): reads the same
	// resource collection as GET /resources, but additionally requires the
	// "pwd" authentication-context value. See middleware.go's RequireACRMiddleware
	// doc comment for why this can't be demonstrated end-to-end against the
	// real token-introspection-service topology today.
	mux.Handle("GET /resources/sensitive", authMiddleware(
		RequireScopeMiddleware("read")(RequireACRMiddleware("pwd")(http.HandlerFunc(h.ListResources))),
	))

	// TraceIDMiddleware must be outermost so trace IDs are in context when
	// LoggingMiddleware reads them (it captures ctx before calling next).
	return httputil.TraceIDMiddleware(
		httputil.RecoveryMiddleware(logger)(
			httputil.LoggingMiddleware(logger)(mux),
		),
	)
}
