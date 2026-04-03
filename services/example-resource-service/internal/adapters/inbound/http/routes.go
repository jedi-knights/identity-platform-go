package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	_ "github.com/ocrosby/identity-platform-go/services/example-resource-service/docs"
)

// NewRouter sets up HTTP routes with JWT auth and scope middleware (Chain of Responsibility).
func NewRouter(h *Handler, logger logging.Logger, signingKey []byte) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	readProtected := JWTAuthMiddleware(signingKey, logger)(
		RequireScopeMiddleware("read")(http.HandlerFunc(h.ListResources)),
	)
	mux.Handle("GET /resources", readProtected)

	readOneProtected := JWTAuthMiddleware(signingKey, logger)(
		RequireScopeMiddleware("read")(http.HandlerFunc(h.GetResource)),
	)
	mux.Handle("GET /resources/{id}", readOneProtected)

	writeProtected := JWTAuthMiddleware(signingKey, logger)(
		RequireScopeMiddleware("write")(http.HandlerFunc(h.CreateResource)),
	)
	mux.Handle("POST /resources", writeProtected)

	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
