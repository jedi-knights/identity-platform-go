package http

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/httputil"
)

const (
	// defaultMaxTrackedKeys caps how many distinct keys one limiter tracks.
	// The key space is attacker-controlled (any email string, any source IP),
	// so without a cap a stream of unique keys grows the map without bound.
	defaultMaxTrackedKeys = 100_000

	// sweepInterval is how often expired buckets are purged. Sweeping is O(n),
	// so it is amortized to at most once per interval instead of per request;
	// expired entries therefore linger at most window+sweepInterval.
	sweepInterval = time.Minute
)

// ResetRateLimits configures the two password-reset endpoints' limiters. A
// zero Max disables the corresponding limiter, so the zero value limits
// nothing.
//
// Limits are per process: with N replicas the effective ceiling is N times
// the configured value (state is not shared; see ADR-0029 for the SPOF
// stance that rules out a single shared limiter).
type ResetRateLimits struct {
	// RequestMax / RequestWindow bound POST /auth/request-password-reset per
	// target email. Keyed on the submitted address, never on whether an account
	// exists, so a 429 reveals nothing about account existence — and it stops
	// an attacker from mail-bombing a victim through us.
	RequestMax    int
	RequestWindow time.Duration

	// RedeemMax / RedeemWindow bound POST /auth/reset-password per client IP
	// (the TCP peer; X-Forwarded-For is deliberately not trusted). Behind a
	// proxy such as login-ui every caller shares the proxy's IP, so this acts
	// as a service-wide ceiling on token guessing and password hashing cost.
	RedeemMax    int
	RedeemWindow time.Duration

	// MaxTrackedKeys bounds each limiter's memory. Zero selects
	// defaultMaxTrackedKeys. When full of live keys, new keys are refused.
	MaxTrackedKeys int

	// Now is the clock; nil selects time.Now. Tests inject a fake.
	Now func() time.Time
}

// windowLimiter is a per-key fixed-window limiter with bounded memory.
// O(1) per request, plus one O(n) sweep per sweepInterval; O(maxKeys) space.
// Safe for concurrent use.
type windowLimiter struct {
	mu        sync.Mutex
	buckets   map[string]windowBucket
	nextSweep time.Time

	max     int
	window  time.Duration
	maxKeys int
	now     func() time.Time
}

type windowBucket struct {
	count int
	reset time.Time
}

// newWindowLimiter returns nil when max <= 0 (limiting disabled). Callers
// treat a nil limiter as "allow everything".
func newWindowLimiter(max int, window time.Duration, maxKeys int, now func() time.Time) *windowLimiter {
	if max <= 0 || window <= 0 {
		return nil
	}
	if maxKeys <= 0 {
		maxKeys = defaultMaxTrackedKeys
	}
	if now == nil {
		now = time.Now
	}
	return &windowLimiter{
		buckets: make(map[string]windowBucket),
		max:     max,
		window:  window,
		maxKeys: maxKeys,
		now:     now,
	}
}

// allow reports whether key may proceed. When it may not, retryAfter is how
// long until a retry can succeed (always at least one second).
func (l *windowLimiter) allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweepLocked(now)

	b, tracked := l.buckets[key]
	switch {
	case tracked && now.Before(b.reset):
		return l.countLocked(key, b, now)
	case !tracked && len(l.buckets) >= l.maxKeys:
		// Fail closed: refusing a new key is safer than unbounded growth.
		return false, l.nextSweep.Sub(now)
	}
	l.buckets[key] = windowBucket{count: 1, reset: now.Add(l.window)}
	return true, 0
}

// countLocked charges one request to a live bucket. Caller holds l.mu.
func (l *windowLimiter) countLocked(key string, b windowBucket, now time.Time) (bool, time.Duration) {
	if b.count >= l.max {
		return false, b.reset.Sub(now)
	}
	b.count++
	l.buckets[key] = b
	return true, 0
}

// sweepLocked purges expired buckets at most once per sweepInterval.
// Caller holds l.mu.
func (l *windowLimiter) sweepLocked(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	for k, b := range l.buckets {
		if !now.Before(b.reset) {
			delete(l.buckets, k)
		}
	}
	l.nextSweep = now.Add(sweepInterval)
}

// WithResetRateLimits enables rate limiting on the password-reset endpoints
// and returns h for chaining. Without it both endpoints are unlimited.
func (h *Handler) WithResetRateLimits(limits ResetRateLimits) *Handler {
	h.requestResetLimiter = newWindowLimiter(limits.RequestMax, limits.RequestWindow, limits.MaxTrackedKeys, limits.Now)
	h.redeemResetLimiter = newWindowLimiter(limits.RedeemMax, limits.RedeemWindow, limits.MaxTrackedKeys, limits.Now)
	return h
}

// writeRateLimited sends a 429 with Retry-After (RFC 6585 §4).
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(math.Ceil(retryAfter.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	httputil.WriteError(w, apperrors.New(apperrors.ErrCodeRateLimit, "too many requests"))
}

// emailLimitKey normalizes an email for limiter keying so case and
// surrounding whitespace cannot be used to dodge the limit.
func emailLimitKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// clientIP returns the TCP peer address without its port. Forwarding
// headers are not consulted: they are client-controlled unless a trusted
// proxy overwrites them.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
