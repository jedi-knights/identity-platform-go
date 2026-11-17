package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/testutil"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// countingResetter records how many times each port method is reached so
// tests can prove a rate-limited request never touches the service.
type countingResetter struct {
	requests atomic.Int32
	resets   atomic.Int32
}

func (c *countingResetter) RequestReset(_ context.Context, _ domain.RequestPasswordResetRequest) error {
	c.requests.Add(1)
	return nil
}

func (c *countingResetter) ResetPassword(_ context.Context, _ domain.ResetPasswordRequest) (*domain.ResetPasswordResponse, error) {
	c.resets.Add(1)
	return &domain.ResetPasswordResponse{UserID: "u-1", Email: "u@example.com"}, nil
}

// fakeClock is a manually advanced clock for window-expiry tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newLimitedRouter(res *countingResetter, limits ResetRateLimits) http.Handler {
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, &fakePreferences{}, res, testutil.NewTestLogger()).
		WithResetRateLimits(limits)
	return NewRouter(h, testutil.NewTestLogger())
}

func postReset(router http.Handler, path, remoteAddr, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func requestResetBody(email string) string {
	b, _ := json.Marshal(map[string]string{"email": email})
	return string(b)
}

func TestRequestPasswordReset_RateLimitedPerEmail(t *testing.T) {
	res := &countingResetter{}
	router := newLimitedRouter(res, ResetRateLimits{RequestMax: 2, RequestWindow: time.Hour})

	for i := 0; i < 2; i++ {
		if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com")); rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204", i+1, rec.Code)
		}
	}
	rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com"))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}
	var body struct{ Code string }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Code != "RATE_LIMIT" {
		t.Errorf("error code = %q, want RATE_LIMIT", body.Code)
	}
	if got := res.requests.Load(); got != 2 {
		t.Errorf("service reached %d times, want 2 (limited call must not reach it)", got)
	}
}

func TestRequestPasswordReset_LimitKeyIsNormalizedEmailNotIP(t *testing.T) {
	res := &countingResetter{}
	router := newLimitedRouter(res, ResetRateLimits{RequestMax: 1, RequestWindow: time.Hour})
	postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com"))

	sameEmailOtherCaseAndIP := postReset(router, "/auth/request-password-reset", "10.0.0.2:2000", requestResetBody("  A@Example.COM "))
	otherEmail := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("b@example.com"))

	if sameEmailOtherCaseAndIP.Code != http.StatusTooManyRequests {
		t.Errorf("same email via different case/IP: status = %d, want 429", sameEmailOtherCaseAndIP.Code)
	}
	if otherEmail.Code != http.StatusNoContent {
		t.Errorf("different email: status = %d, want 204 (limit is per email)", otherEmail.Code)
	}
}

func TestRequestPasswordReset_MalformedBodyDoesNotConsumeQuota(t *testing.T) {
	res := &countingResetter{}
	router := newLimitedRouter(res, ResetRateLimits{RequestMax: 1, RequestWindow: time.Hour})

	for i := 0; i < 3; i++ {
		if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", "{not json"); rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed body: status = %d, want 400", rec.Code)
		}
	}

	if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com")); rec.Code != http.StatusNoContent {
		t.Errorf("valid request after malformed ones: status = %d, want 204", rec.Code)
	}
}

func TestRequestPasswordReset_QuotaRestoredAfterWindow(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	router := newLimitedRouter(&countingResetter{}, ResetRateLimits{RequestMax: 1, RequestWindow: time.Hour, Now: clock.now})
	postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com"))
	if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request in window: status = %d, want 429", rec.Code)
	}

	clock.advance(time.Hour + time.Second)

	if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com")); rec.Code != http.StatusNoContent {
		t.Errorf("after window: status = %d, want 204", rec.Code)
	}
}

func TestRequestPasswordReset_RetryAfterReflectsRemainingWindow(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	router := newLimitedRouter(&countingResetter{}, ResetRateLimits{RequestMax: 1, RequestWindow: time.Hour, Now: clock.now})
	postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com"))
	clock.advance(30 * time.Minute)

	rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com"))

	if got := rec.Header().Get("Retry-After"); got != "1800" {
		t.Errorf("Retry-After = %q, want 1800 (30 min left of the 1 h window)", got)
	}
}

func TestResetPassword_RateLimitedPerClientIP(t *testing.T) {
	res := &countingResetter{}
	router := newLimitedRouter(res, ResetRateLimits{RedeemMax: 2, RedeemWindow: 15 * time.Minute})
	body := `{"token":"t","new_password":"correct horse battery"}`

	for i := 0; i < 2; i++ {
		if rec := postReset(router, "/auth/reset-password", "10.0.0.1:1000", body); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}
	limited := postReset(router, "/auth/reset-password", "10.0.0.1:2222", body)
	otherIP := postReset(router, "/auth/reset-password", "10.0.0.9:1000", body)

	if limited.Code != http.StatusTooManyRequests {
		t.Errorf("third request from same IP (new port): status = %d, want 429", limited.Code)
	}
	if limited.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}
	if otherIP.Code != http.StatusOK {
		t.Errorf("different IP: status = %d, want 200", otherIP.Code)
	}
	if got := res.resets.Load(); got != 3 {
		t.Errorf("service reached %d times, want 3 (limited call must not reach it)", got)
	}
}

func TestResetEndpoints_UnlimitedWhenNotConfigured(t *testing.T) {
	res := &countingResetter{}
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, &fakePreferences{}, res, testutil.NewTestLogger())
	router := NewRouter(h, testutil.NewTestLogger())

	for i := 0; i < 50; i++ {
		if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com")); rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204 with no limits configured", i+1, rec.Code)
		}
	}
}

func TestResetRateLimits_ZeroMaxDisablesThatEndpointOnly(t *testing.T) {
	router := newLimitedRouter(&countingResetter{}, ResetRateLimits{RequestMax: 0, RedeemMax: 1, RedeemWindow: time.Hour})
	body := `{"token":"t","new_password":"correct horse battery"}`

	for i := 0; i < 5; i++ {
		if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com")); rec.Code != http.StatusNoContent {
			t.Fatalf("request limiter should be off: status = %d", rec.Code)
		}
	}
	postReset(router, "/auth/reset-password", "10.0.0.1:1000", body)
	if rec := postReset(router, "/auth/reset-password", "10.0.0.1:1000", body); rec.Code != http.StatusTooManyRequests {
		t.Errorf("redeem limiter should still apply: status = %d, want 429", rec.Code)
	}
}

func TestResetRateLimits_TrackedKeysAreBounded(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	router := newLimitedRouter(&countingResetter{}, ResetRateLimits{
		RequestMax: 1, RequestWindow: time.Hour, MaxTrackedKeys: 3, Now: clock.now,
	})
	for _, e := range []string{"a@x.com", "b@x.com", "c@x.com"} {
		postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody(e))
	}

	overflow := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("d@x.com"))
	clock.advance(time.Hour + time.Second)
	afterExpiry := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("d@x.com"))

	if overflow.Code != http.StatusTooManyRequests {
		t.Errorf("new key past the cap: status = %d, want 429 (fail closed, memory stays bounded)", overflow.Code)
	}
	if afterExpiry.Code != http.StatusNoContent {
		t.Errorf("after old keys expire: status = %d, want 204", afterExpiry.Code)
	}
}

func TestRequestPasswordReset_ConcurrentCallersNeverExceedLimit(t *testing.T) {
	router := newLimitedRouter(&countingResetter{}, ResetRateLimits{RequestMax: 10, RequestWindow: time.Hour})
	var accepted atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := postReset(router, "/auth/request-password-reset", "10.0.0.1:1000", requestResetBody("a@example.com")); rec.Code == http.StatusNoContent {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := accepted.Load(); got != 10 {
		t.Errorf("accepted %d of 100 concurrent requests, want exactly 10", got)
	}
}

func postResetFrom(router http.Handler, peer, xff string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(`{"token":"t","new_password":"correct horse battery"}`))
	req.Header.Set("Content-Type", "application/json")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	req.RemoteAddr = peer
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func trustedLimits() ResetRateLimits {
	return ResetRateLimits{
		RedeemMax:      1,
		RedeemWindow:   15 * time.Minute,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}
}

func TestResetPassword_TrustedProxyForwardedIPIsTheLimitKey(t *testing.T) {
	router := newLimitedRouter(&countingResetter{}, trustedLimits())

	first := postResetFrom(router, "10.0.0.5:1000", "203.0.113.7")
	sameClient := postResetFrom(router, "10.0.0.5:1001", "203.0.113.7")
	otherClient := postResetFrom(router, "10.0.0.5:1002", "203.0.113.8")

	if first.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", first.Code)
	}
	if sameClient.Code != http.StatusTooManyRequests {
		t.Errorf("same forwarded client: status = %d, want 429", sameClient.Code)
	}
	if otherClient.Code != http.StatusOK {
		t.Errorf("different forwarded client behind same proxy: status = %d, want 200 (must not share one bucket)", otherClient.Code)
	}
}

func TestResetPassword_UntrustedPeerCannotSpoofForwardedIP(t *testing.T) {
	router := newLimitedRouter(&countingResetter{}, trustedLimits())

	first := postResetFrom(router, "198.51.100.9:1000", "203.0.113.1")
	spoofed := postResetFrom(router, "198.51.100.9:1001", "203.0.113.2")

	if first.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", first.Code)
	}
	if spoofed.Code != http.StatusTooManyRequests {
		t.Errorf("rotating X-Forwarded-For from an untrusted peer: status = %d, want 429", spoofed.Code)
	}
}

func TestResetPassword_TrustedProxyWithBadForwardedHeaderFallsBackToPeer(t *testing.T) {
	for _, xff := range []string{"", "not-an-ip", "203.0.113.7, garbage"} {
		router := newLimitedRouter(&countingResetter{}, trustedLimits())
		postResetFrom(router, "10.0.0.5:1000", xff)
		if rec := postResetFrom(router, "10.0.0.5:1001", xff); rec.Code != http.StatusTooManyRequests {
			t.Errorf("X-Forwarded-For %q: status = %d, want 429 keyed on the proxy", xff, rec.Code)
		}
	}
}
