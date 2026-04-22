package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	_ "github.com/ocrosby/identity-platform-go/services/api-gateway/docs"
)

// NewRouter registers all routes and applies the middleware chain.
// System routes (/health, /swagger/) are registered explicitly; all other paths
// fall through to the gateway Proxy handler.
//
// Middleware order (outermost to innermost):
//
//	RecoveryMiddleware → LoggingMiddleware → TraceIDMiddleware → ServeMux
func NewRouter(h *Handler, logger logging.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", h.Health)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Catch-all: every unmatched path is treated as a proxy target.
	mux.HandleFunc("/", h.Proxy)

	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(mux),
		),
	)
}
