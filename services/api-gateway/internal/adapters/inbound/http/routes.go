package http

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// NewRouter sets up the HTTP routes and applies the middleware chain.
//
// Middleware order (outermost to innermost):
//
//	Recovery → Logging → TraceID → CORS → Handler
//
// The health endpoint is exempt from rate limiting. It is registered on a
// separate mux that sits outside the rate-limit layer so monitoring tools
// always get a response regardless of traffic volume.
func NewRouter(h *Handler, logger logging.Logger, limiter ports.RateLimiter, cors config.CORSConfig) http.Handler {
	// Top-level mux: health is served directly, everything else is
	// delegated to the rate-limited proxy mux.
	top := http.NewServeMux()
	top.HandleFunc("GET /health", h.Health)

	// Proxy mux: all proxied traffic goes through rate limiting.
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", h.Proxy)

	rateLimited := RateLimitMiddleware(limiter, logger)(proxyMux)
	top.Handle("/", rateLimited)

	return httputil.RecoveryMiddleware(logger)(
		httputil.LoggingMiddleware(logger)(
			httputil.TraceIDMiddleware(
				CORSMiddleware(cors)(top),
			),
		),
	)
}
