package http

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// CORSMiddleware returns middleware that handles CORS preflight and response headers.
//
// For preflight (OPTIONS) requests, it writes the CORS headers and returns 204.
// For all other requests, it adds CORS headers and delegates to the next handler.
func CORSMiddleware(cfg config.CORSConfig) func(http.Handler) http.Handler {
	origins := strings.Join(cfg.AllowedOrigins, ", ")
	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAgeSecs)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", origins)
			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			w.Header().Set("Access-Control-Max-Age", maxAge)

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware returns middleware that enforces per-client rate limiting.
//
// The client is identified by IP address extracted from RemoteAddr.
// When a client exceeds the rate limit, a 429 Too Many Requests response
// is returned with a Retry-After header.
func RateLimitMiddleware(limiter ports.RateLimiter, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r.RemoteAddr)

			if !limiter.Allow(ip) {
				logger.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractIP strips the port from RemoteAddr to get the client IP.
// Note: when the gateway is behind a load balancer, RemoteAddr is the
// balancer's IP. A production deployment should key on X-Forwarded-For
// or X-Real-IP instead.
func extractIP(remoteAddr string) string {
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}
	return remoteAddr
}
