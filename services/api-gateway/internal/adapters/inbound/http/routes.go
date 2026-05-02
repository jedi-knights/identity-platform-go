package http

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	_ "github.com/ocrosby/identity-platform-go/services/api-gateway/docs"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// NewRouter registers all routes and applies the middleware chain.
//
// Design: Decorator pattern — each middleware wraps the next handler, adding
// one cross-cutting concern without modifying the handlers themselves.
//
// Full execution order (outermost → innermost):
//
//	CompressionMiddleware (optional)
//	  → RecoveryMiddleware
//	    → tracingMiddleware (OTel, optional)
//	      → TraceIDMiddleware
//	        → RequestIDMiddleware
//	          → LoggingMiddleware
//	            → CORSMiddleware
//	              → mux
//	                → [system routes: /health, /ready, /swagger/, /metrics]
//	                → [proxy catch-all]:
//	                    JWTMiddleware (optional)
//	                      → IPFilterMiddleware (optional)
//	                        → ConcurrencyMiddleware (optional)
//	                          → RateLimitMiddleware (optional)
//	                            → CacheMiddleware (optional)
//	                              → Proxy
//
// Ordering rationale:
//   - Auth before IP filter before rate-limit: invalid tokens rejected first
//     (no resources consumed), then IP block, then token bucket.
//   - Cache after rate-limit: rate-limited requests never hit the cache, saving
//     a cache lookup on rejected traffic.
//   - System routes bypass auth, IP filter, rate-limit, and cache entirely.
//   - Compression is outermost so it can compress error responses from Recovery.
//
// Parameters:
//   - corsCfg:            CORS settings; an empty struct disables CORS headers.
//   - authMiddleware:     JWT middleware; nil disables authentication.
//   - ipFilterMiddleware: IP allow/deny middleware; nil disables IP filtering.
//   - limiter:            rate limiter; nil disables rate limiting.
//   - concLimiter:        concurrency limiter; nil disables concurrency limiting.
//   - rateLimitKeySource: key extraction mode passed to RateLimitMiddleware/ConcurrencyMiddleware.
//   - metricsHandler:     Prometheus HTTP handler; nil skips /metrics.
//   - tracingMiddleware:  OTel HTTP handler wrapper; nil disables tracing.
//   - compressionMW:      Gzip middleware; nil disables compression.
//   - cacheMW:            Response cache middleware; nil disables caching.
func NewRouter(
	h *Handler,
	logger logging.Logger,
	corsCfg config.CORSConfig,
	authMiddleware func(http.Handler) http.Handler,
	ipFilterMiddleware func(http.Handler) http.Handler,
	limiter ports.RateLimiter,
	concLimiter ports.ConcurrencyLimiter,
	rateLimitKeySource string,
	metricsHandler http.Handler,
	tracingMiddleware func(http.Handler) http.Handler,
	compressionMW func(http.Handler) http.Handler,
	cacheMW func(http.Handler) http.Handler,
) http.Handler {
	mux := http.NewServeMux()

	// System routes — always reachable, never rate-limited or auth-gated.
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /ready", h.Ready)
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	if metricsHandler != nil {
		mux.Handle("GET /metrics", metricsHandler)
	}

	// Proxy catch-all — execution order: auth → ip-filter → concurrency → rate-limit → cache → proxy.
	mux.Handle("/", buildProxyChain(h, logger, authMiddleware, ipFilterMiddleware, limiter, concLimiter, rateLimitKeySource, cacheMW))

	// Outer chain — applied to every request including system routes.
	// Build inside-out; execution order is the reverse.
	outer := CORSMiddleware(corsCfg)(mux)
	outer = httputil.LoggingMiddleware(logger)(outer)
	outer = RequestIDMiddleware(logger)(outer)
	outer = httputil.TraceIDMiddleware(outer)
	if tracingMiddleware != nil {
		outer = tracingMiddleware(outer)
	}
	outer = httputil.RecoveryMiddleware(logger)(outer)
	if compressionMW != nil {
		outer = compressionMW(outer)
	}
	return outer
}

// buildProxyChain assembles the per-proxy-request middleware stack inside-out so
// that execution order is: auth → ip-filter → concurrency → rate-limit → cache → proxy.
// Nil middlewares are skipped; nil limiters skip their respective middleware entirely.
// Extracted from NewRouter to keep its cyclomatic complexity within the project limit.
func buildProxyChain(
	h *Handler,
	logger logging.Logger,
	authMW func(http.Handler) http.Handler,
	ipFilterMW func(http.Handler) http.Handler,
	limiter ports.RateLimiter,
	concLimiter ports.ConcurrencyLimiter,
	rateLimitKeySource string,
	cacheMW func(http.Handler) http.Handler,
) http.Handler {
	var ph http.Handler = http.HandlerFunc(h.Proxy)
	if cacheMW != nil {
		ph = cacheMW(ph)
	}
	if limiter != nil {
		ph = RateLimitMiddleware(limiter, rateLimitKeySource, logger)(ph)
	}
	if concLimiter != nil {
		ph = ConcurrencyMiddleware(concLimiter, rateLimitKeySource, logger)(ph)
	}
	if ipFilterMW != nil {
		ph = ipFilterMW(ph)
	}
	if authMW != nil {
		ph = authMW(ph)
	}
	return ph
}
