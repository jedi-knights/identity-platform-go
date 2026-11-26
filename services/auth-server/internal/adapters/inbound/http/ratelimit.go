package http

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/httputil"
	"golang.org/x/time/rate"
)

// idleVisitorTTL evicts a visitor's bucket after this long of no
// activity. Keeps the sync.Map bounded without external state; a
// long-idle attacker starts fresh, which is the right trade for an
// endpoint hit at human cadence.
const idleVisitorTTL = 10 * time.Minute

// gcInterval is how often the eviction sweep runs. Short enough to
// bound memory, long enough that the sweep's own work is negligible.
const gcInterval = time.Minute

// TokenRateLimiterConfig holds the per-IP rate-limit configuration for
// the /oauth/token endpoint. RequestsPerMinute is the only knob
// operators need; Logger is required so 429s are observable.
type TokenRateLimiterConfig struct {
	// RequestsPerMinute caps the token-bucket refill rate AND the
	// burst for each client IP. 0 disables the limiter entirely
	// (useful when a different layer handles rate limiting);
	// negative values are a construction error.
	RequestsPerMinute int

	// ClientIPHeader is the request header carrying the real client
	// IP after an edge proxy (Fly, Cloudflare, etc.) rewrites the
	// connection source. Empty means "use r.RemoteAddr" — correct
	// for local dev and any deploy not fronted by an edge.
	ClientIPHeader string

	// Logger captures one record per 429. Required; nil is a
	// construction error (silent 429s are an observability bug).
	Logger logging.Logger
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewTokenRateLimiter returns an http.Handler wrapper that enforces a
// per-IP token-bucket rate limit. Designed for /oauth/token specifically
// — the endpoint where a password-spray attacker would try many
// (client_id, client_secret) pairs to enumerate or brute-force a
// client's credentials.
//
// State lives in process memory (sync.Map of *rate.Limiter) with
// background eviction of idle entries. State loss on restart is
// accepted: an attacker gets a fresh bucket after a roll, which is
// minor at Phase 1 scale and matches the posture of the rest of the
// auth stack per ADR-0029.
func NewTokenRateLimiter(cfg TokenRateLimiterConfig) (func(http.Handler) http.Handler, error) {
	if cfg.RequestsPerMinute < 0 {
		return nil, errors.New("ratelimit: RequestsPerMinute must be >= 0")
	}
	if cfg.Logger == nil {
		return nil, errors.New("ratelimit: Logger is required")
	}

	// Zero disables the limiter entirely — every request passes
	// through. Build a trivial pass-through to avoid paying for the
	// map lookup or limiter construction on every request.
	if cfg.RequestsPerMinute == 0 {
		return func(next http.Handler) http.Handler { return next }, nil
	}

	visitors := &sync.Map{}
	// rate.Every(interval) refills one token per interval. A
	// per-minute cap of N means one token every 60/N seconds. Burst
	// = N so a client that hasn't called in a while gets up to N
	// requests immediately, matching operator intuition for "N/min".
	refillEvery := time.Minute / time.Duration(cfg.RequestsPerMinute)
	burst := cfg.RequestsPerMinute

	// Retry-After suggestion rounded up to the nearest second,
	// floored at 1s per RFC 7231 §7.1.3 (positive integer required).
	retryAfterSeconds := int((refillEvery + time.Second - 1) / time.Second)
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}

	startGC(visitors)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := rateLimitClientIP(r, cfg.ClientIPHeader)
			lim := loadOrStore(visitors, ip, refillEvery, burst)
			if !lim.Allow() {
				cfg.Logger.WarnContext(r.Context(), "ratelimit: /oauth/token caller over limit",
					"ip", ip,
					"path", r.URL.Path)
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeRateLimit, "rate limit exceeded"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// loadOrStore returns the limiter for ip, creating one on first sight.
// lastSeen advances on every call so active IPs survive GC.
func loadOrStore(visitors *sync.Map, ip string, every time.Duration, burst int) *rate.Limiter {
	now := time.Now()
	if raw, ok := visitors.Load(ip); ok {
		v := raw.(*visitor)
		v.lastSeen = now
		return v.limiter
	}
	v := &visitor{
		limiter:  rate.NewLimiter(rate.Every(every), burst),
		lastSeen: now,
	}
	actual, loaded := visitors.LoadOrStore(ip, v)
	if loaded {
		av := actual.(*visitor)
		av.lastSeen = now
		return av.limiter
	}
	return v.limiter
}

// startGC launches the eviction sweeper. Runs forever — the service
// process owns the limiter for its lifetime.
func startGC(visitors *sync.Map) {
	go func() {
		ticker := time.NewTicker(gcInterval)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-idleVisitorTTL)
			visitors.Range(func(k, raw any) bool {
				v := raw.(*visitor)
				if v.lastSeen.Before(cutoff) {
					visitors.Delete(k)
				}
				return true
			})
		}
	}()
}

// rateLimitClientIP picks the caller's IP from the configured header when set,
// falling back to r.RemoteAddr. The header's first entry wins when a
// comma-separated list is present (Fly-Client-IP is single-value;
// X-Forwarded-For is CSV). A missing header falls to RemoteAddr so
// attackers behind a mis-configured edge can't share one bucket.
func rateLimitClientIP(r *http.Request, header string) string {
	if header != "" {
		if v := strings.TrimSpace(r.Header.Get(header)); v != "" {
			if idx := strings.IndexByte(v, ','); idx >= 0 {
				v = strings.TrimSpace(v[:idx])
			}
			return v
		}
	}
	// r.RemoteAddr is "host:port"; strip the port so bursts across
	// ephemeral ports from the same host share one bucket.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
