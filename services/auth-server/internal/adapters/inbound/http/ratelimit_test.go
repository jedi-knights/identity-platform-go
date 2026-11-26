// TDD tests for the per-IP token-bucket limiter on /oauth/token.
// Red-first — named functions appear in tests before the production
// file declares them.
package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
)

func discardLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.New(logging.Config{Output: io.Discard})
}

// buildLimiter wires the middleware around a counter-recording handler.
func buildLimiter(t *testing.T, rpm int) (http.Handler, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	mw, err := authhttp.NewTokenRateLimiter(authhttp.TokenRateLimiterConfig{
		RequestsPerMinute: rpm,
		ClientIPHeader:    "X-Test-IP",
		Logger:            discardLogger(t),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	return mw(next), &hits
}

func doReq(h http.Handler, ip string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", http.NoBody)
	if ip != "" {
		req.Header.Set("X-Test-IP", ip)
	}
	h.ServeHTTP(rec, req)
	return rec
}

// --- below / at / over the burst ---

func TestTokenRateLimiter_AllowsBelowBurst(t *testing.T) {
	t.Parallel()
	h, hits := buildLimiter(t, 10)
	for i := 0; i < 5; i++ {
		if rec := doReq(h, "1.2.3.4"); rec.Code != http.StatusOK {
			t.Fatalf("req %d: status = %d, want 200", i, rec.Code)
		}
	}
	if hits.Load() != 5 {
		t.Errorf("hits = %d, want 5", hits.Load())
	}
}

func TestTokenRateLimiter_429OverBurst(t *testing.T) {
	t.Parallel()
	rpm := 3
	h, hits := buildLimiter(t, rpm)
	// Deplete the burst.
	for i := 0; i < rpm; i++ {
		if rec := doReq(h, "1.2.3.4"); rec.Code != http.StatusOK {
			t.Fatalf("warm %d: %d", i, rec.Code)
		}
	}
	// N+1 must 429.
	rec := doReq(h, "1.2.3.4")
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rec.Code)
	}
	if hits.Load() != int64(rpm) {
		t.Errorf("hits = %d past burst, want %d", hits.Load(), rpm)
	}
}

// 429 responses must carry Retry-After so clients know how long to
// back off. RFC 7231 §7.1.3 requires a positive integer (seconds).
func TestTokenRateLimiter_RetryAfterHeaderOn429(t *testing.T) {
	t.Parallel()
	h, _ := buildLimiter(t, 1)
	_ = doReq(h, "1.2.3.4") // drain
	rec := doReq(h, "1.2.3.4")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	got := rec.Header().Get("Retry-After")
	if got == "" {
		t.Error("Retry-After header missing")
	} else if n, err := strconv.Atoi(got); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want positive int seconds", got)
	}
}

// --- per-IP isolation: one attacker IP can't starve another legit IP ---

func TestTokenRateLimiter_PerIPBuckets(t *testing.T) {
	t.Parallel()
	h, _ := buildLimiter(t, 2)
	// Deplete IP A.
	for i := 0; i < 2; i++ {
		_ = doReq(h, "1.1.1.1")
	}
	if rec := doReq(h, "1.1.1.1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("A over limit: %d", rec.Code)
	}
	// IP B must still have its full budget.
	if rec := doReq(h, "2.2.2.2"); rec.Code != http.StatusOK {
		t.Errorf("B: %d, want 200 (separate bucket)", rec.Code)
	}
}

// --- config boundary ---

// RPM = 0 disables the limiter entirely (useful when a different
// layer handles the limit); matches cutline's ratelimit package shape.
func TestTokenRateLimiter_ZeroRPMDisables(t *testing.T) {
	t.Parallel()
	h, hits := buildLimiter(t, 0)
	for i := 0; i < 20; i++ {
		if rec := doReq(h, "1.2.3.4"); rec.Code != http.StatusOK {
			t.Fatalf("req %d: %d", i, rec.Code)
		}
	}
	if hits.Load() != 20 {
		t.Errorf("hits = %d, want 20", hits.Load())
	}
}

func TestTokenRateLimiter_RejectsNegativeRPM(t *testing.T) {
	t.Parallel()
	_, err := authhttp.NewTokenRateLimiter(authhttp.TokenRateLimiterConfig{
		RequestsPerMinute: -5,
		Logger:            discardLogger(t),
	})
	if err == nil {
		t.Error("NewTokenRateLimiter(-5) returned nil error")
	}
}

func TestTokenRateLimiter_RejectsMissingLogger(t *testing.T) {
	t.Parallel()
	_, err := authhttp.NewTokenRateLimiter(authhttp.TokenRateLimiterConfig{
		RequestsPerMinute: 10,
	})
	if err == nil {
		t.Error("NewTokenRateLimiter(nil logger) returned nil error")
	}
}

// --- client-IP source selection ---

// With an empty ClientIPHeader (local dev, no edge proxy), the
// limiter falls back to r.RemoteAddr so bursts from the same host
// collapse into one bucket.
func TestTokenRateLimiter_FallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()
	mw, err := authhttp.NewTokenRateLimiter(authhttp.TokenRateLimiterConfig{
		RequestsPerMinute: 1,
		ClientIPHeader:    "",
		Logger:            discardLogger(t),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var hits atomic.Int64
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", http.NoBody)
		req.RemoteAddr = "127.0.0.1:9000"
		h.ServeHTTP(rec, req)
		switch i {
		case 0:
			if rec.Code != http.StatusOK {
				t.Fatalf("first: %d, want 200", rec.Code)
			}
		case 1:
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("second: %d, want 429 (same RemoteAddr)", rec.Code)
			}
		}
	}
}

// --- shape: 429 body is the standard apperrors envelope so SDK
//     predicates (IsRateLimited) can read it unchanged ---

func TestTokenRateLimiter_429BodyShape(t *testing.T) {
	t.Parallel()
	h, _ := buildLimiter(t, 1)
	_ = doReq(h, "1.2.3.4")
	rec := doReq(h, "1.2.3.4")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	body := rec.Body.String()
	// The response must identify itself as a rate-limit response so
	// SDK/client predicate code can distinguish it from other 429s.
	if body == "" {
		t.Error("empty 429 body — SDK predicates need a code field")
	}
}
