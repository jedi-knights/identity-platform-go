package http

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/ports"
)

// Ensure domain.IntrospectionResult is referenced so the package is included
// in Swagger doc generation scans.
var _ *domain.IntrospectionResult

// Handler holds HTTP handler dependencies.
type Handler struct {
	introspector        ports.Introspector
	logger              logging.Logger
	introspectionSecret string
	rateLimiter         *fixedWindowLimiter
}

// NewHandler creates a Handler. introspectionSecret is a pre-shared secret for the
// /introspect endpoint (INTROSPECT_SECRET_KEY). When non-empty, callers must supply
// Authorization: Bearer <secret>. When empty, no caller authentication is enforced.
func NewHandler(introspector ports.Introspector, logger logging.Logger, introspectionSecret string) *Handler {
	return &Handler{
		introspector:        introspector,
		logger:              logger,
		introspectionSecret: introspectionSecret,
		rateLimiter:         newFixedWindowLimiter(20, time.Minute),
	}
}

// inactive is the RFC 7662 §2.2 response for any token that cannot be confirmed active.
var inactive = map[string]bool{"active": false}

// Introspect handles POST /introspect.
//
// Per RFC 7662 §2.1 the endpoint requires some form of authorization.
// When introspectionSecret is set, callers must supply Authorization: Bearer <secret>.
//
// Per RFC 7662 §2.2 this endpoint ALWAYS returns HTTP 200 for token validation results.
// Invalid, expired, revoked, or missing tokens return {"active": false}.
//
// Per RFC 7662 §2.4 responses must include Cache-Control: no-store and Pragma: no-cache.
//
// @Summary      Introspect token
// @Description  Validates a JWT token and returns metadata per RFC 7662. Always returns HTTP 200.
// @Tags         introspection
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token  formData  string  true  "JWT token to introspect"
// @Success      200  {object}  domain.IntrospectionResult
// @Router       /introspect [post]
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	// RFC 7662 §2.4: responses must not be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// RFC 6819 §4.3.2: rate-limit by client IP to slow brute-force attacks.
	if !h.rateLimiter.Allow(clientIP(r)) {
		// RFC 6585 §4: include Retry-After on 429 responses.
		w.Header().Set("Retry-After", "60")
		httputil.WriteJSON(w, http.StatusTooManyRequests, map[string]string{
			"error":             "too_many_requests",
			"error_description": "rate limit exceeded",
		})
		return
	}

	// RFC 7662 §2.1: authenticate the caller.
	if !h.authenticateCaller(w, r) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.logger.Error("failed to parse introspect form", "error", err.Error())
		httputil.WriteJSON(w, http.StatusOK, inactive)
		return
	}

	raw := r.FormValue("token")
	if raw == "" {
		// Per RFC 7662 §2.2: a missing token cannot be active.
		httputil.WriteJSON(w, http.StatusOK, inactive)
		return
	}

	result, err := h.introspector.Introspect(r.Context(), raw)
	if err != nil {
		// Per RFC 7662 §2.2, infrastructure failures must not expose errors to the caller.
		// Log for observability, then return {active: false} (fail closed).
		h.logger.Error("introspection failed", "error", err.Error())
		httputil.WriteJSON(w, http.StatusOK, inactive)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, result)
}

// Health handles GET /health.
//
// @Summary      Health check
// @Description  Returns service health status
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// authenticateCaller enforces RFC 7662 §2.1 caller authentication when a
// pre-shared secret is configured. Returns true when auth passes or is not
// required. Writes 401 and returns false when authentication fails.
func (h *Handler) authenticateCaller(w http.ResponseWriter, r *http.Request) bool {
	if h.introspectionSecret == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if !strings.HasPrefix(auth, "Bearer ") || subtle.ConstantTimeCompare([]byte(token), []byte(h.introspectionSecret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="token-introspection-service"`)
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "invalid introspection secret",
		})
		return false
	}
	return true
}

// clientIP extracts the request's remote IP for rate-limiting.
// Strips the port if present.
func clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	return ip
}

// fixedWindowLimiter is a per-key fixed-window rate limiter.
// maxReqs requests are allowed per window; excess requests are rejected.
// Expired entries are evicted lazily on each window reset to prevent
// unbounded map growth under high cardinality of unique keys.
// Thread-safe via sync.Mutex.
type fixedWindowLimiter struct {
	mu      sync.Mutex
	buckets map[string]windowBucket
	maxReqs int
	window  time.Duration
}

type windowBucket struct {
	count int
	reset time.Time
}

func newFixedWindowLimiter(maxReqs int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		buckets: make(map[string]windowBucket),
		maxReqs: maxReqs,
		window:  window,
	}
}

// Allow reports whether a request from key is within the rate limit.
func (l *fixedWindowLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		for k, v := range l.buckets {
			if now.After(v.reset) {
				delete(l.buckets, k)
			}
		}
		l.buckets[key] = windowBucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	if b.count >= l.maxReqs {
		return false
	}
	b.count++
	l.buckets[key] = b
	return true
}
