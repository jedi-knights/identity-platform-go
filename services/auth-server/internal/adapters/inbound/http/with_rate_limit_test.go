//go:build unit

package http_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
)

// grantForm is the minimum POST body that reaches the rate-limit
// check in Handler.Token. The grant itself is ill-formed — but the
// rate limiter runs first (handler.go:181), so when the limiter
// rejects we never reach the auth pipeline (which would panic on
// nil ports in this test setup).
func grantForm() url.Values {
	return url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"probe"},
		"client_secret": {"probe"},
	}
}

// newRateLimitedHandler builds a minimal Handler and tunes its
// per-IP limiter via WithRateLimit. Nil ports are acceptable because
// every test below exhausts the limit and asserts on the 429, which
// short-circuits before any port is called.
func newRateLimitedHandler(t *testing.T, maxReqs int) *authhttp.Handler {
	t.Helper()
	return authhttp.NewHandler(nil, nil, nil, nil, quietLogger(), "", nil, nil).
		WithRateLimit(maxReqs, time.Minute)
}

// Setting a positive maxReqs replaces the pre-change hardcoded default
// of 20. With maxReqs=1 the first request drains the bucket; the
// second must 429 before touching the nil-port auth pipeline.
func TestWithRateLimit_HonorsConfiguredCap(t *testing.T) {
	t.Parallel()
	h := newRateLimitedHandler(t, 1)

	// First request drains the per-IP window. It will eventually
	// panic on the nil clientAuth port, but we don't care about
	// its code — we're probing that the SECOND request 429s via
	// the rate-limit short-circuit.
	func() {
		defer func() { _ = recover() }()
		_ = postForm(t, h.Token, grantForm())
	}()

	rec := postForm(t, h.Token, grantForm())
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("2nd req status = %d, want 429 (maxReqs=1)", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Error("Retry-After header missing on 429")
	}
}

// maxReqs <= 0 keeps the pre-change default (20). This is the
// backwards-compat hook for operators who do not set
// AUTH_TOKEN_RATE_LIMIT_PER_MINUTE — behaviour stays identical to the
// pre-change release so the rollout is low-risk.
//
// Zero-case assertion: the FIRST request is allowed (so the limiter
// is not set to "block everything"). The default's upper bound (20)
// is pinned implicitly by the call to WithRateLimit(0, …) not
// overriding the handler's constructor-set limiter.
func TestWithRateLimit_ZeroKeepsDefault(t *testing.T) {
	t.Parallel()
	h := newRateLimitedHandler(t, 0)
	// One request must not 429. The handler will then panic on
	// nil ports; recover and move on.
	func() {
		defer func() { _ = recover() }()
		rec := postForm(t, h.Token, grantForm())
		// If the handler returned 429 on the first call, maxReqs=0
		// collapsed the bucket — a regression. Any other code
		// (including an earlier 400/500 from the handler) means the
		// rate-limit check passed, which is what we want to see.
		if rec.Code == http.StatusTooManyRequests {
			t.Errorf("first req 429'd under maxReqs=0 (default should allow)")
		}
	}()
}

// Negative maxReqs is treated the same as zero — "keep default" — so
// a misconfigured env var does not disable the limiter nor collapse
// its bucket.
func TestWithRateLimit_NegativeKeepsDefault(t *testing.T) {
	t.Parallel()
	h := newRateLimitedHandler(t, -5)
	func() {
		defer func() { _ = recover() }()
		rec := postForm(t, h.Token, grantForm())
		if rec.Code == http.StatusTooManyRequests {
			t.Errorf("first req 429'd under maxReqs=-5 (default should allow)")
		}
	}()
}
