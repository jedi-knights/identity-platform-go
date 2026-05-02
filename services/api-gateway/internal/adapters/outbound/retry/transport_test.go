//go:build unit

package retry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/retry"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// countingTransport records call count and returns a fixed status code each call.
type countingTransport struct {
	calls    int
	statuses []int // returned in order; last entry repeated if exhausted
}

func (c *countingTransport) Forward(w http.ResponseWriter, _ *http.Request, _ *domain.Route) error {
	status := c.statuses[len(c.statuses)-1]
	if c.calls < len(c.statuses) {
		status = c.statuses[c.calls]
	}
	c.calls++
	w.WriteHeader(status)
	return nil
}

var _ ports.UpstreamTransport = (*countingTransport)(nil)

func globalCfg(enabled bool, maxAttempts int, statuses []int) domain.RetryConfig {
	return domain.RetryConfig{
		Enabled:          enabled,
		MaxAttempts:      maxAttempts,
		InitialBackoffMs: 1, // keep tests fast
		Multiplier:       2,
		RetryableStatus:  statuses,
	}
}

func noRouteRetry() *domain.Route {
	return &domain.Route{Name: "svc", Upstream: domain.UpstreamTarget{URL: "http://up"}}
}

func TestRetryTransport_PassthroughWhenDisabled(t *testing.T) {
	inner := &countingTransport{statuses: []int{http.StatusBadGateway}}
	tr := retry.NewTransport(inner, globalCfg(false, 3, []int{502}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, noRouteRetry())

	if inner.calls != 1 {
		t.Errorf("calls = %d, want 1 (disabled retry must not retry)", inner.calls)
	}
}

func TestRetryTransport_PassthroughWhenMaxAttemptsOne(t *testing.T) {
	inner := &countingTransport{statuses: []int{http.StatusBadGateway}}
	tr := retry.NewTransport(inner, globalCfg(true, 1, []int{502}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, noRouteRetry())

	if inner.calls != 1 {
		t.Errorf("calls = %d, want 1 (max_attempts=1 means no retry)", inner.calls)
	}
}

func TestRetryTransport_SuccessOnFirstAttemptNoRetry(t *testing.T) {
	inner := &countingTransport{statuses: []int{http.StatusOK}}
	tr := retry.NewTransport(inner, globalCfg(true, 3, []int{502, 503, 504}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, noRouteRetry())

	if inner.calls != 1 {
		t.Errorf("calls = %d, want 1 (success on first attempt must not retry)", inner.calls)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRetryTransport_RetriesOnRetryableStatus(t *testing.T) {
	// First two calls return 502 (retryable), third returns 200 (success).
	inner := &countingTransport{statuses: []int{502, 502, 200}}
	tr := retry.NewTransport(inner, globalCfg(true, 3, []int{502}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, noRouteRetry())

	if inner.calls != 3 {
		t.Errorf("calls = %d, want 3 (two retries)", inner.calls)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (success after retries)", rr.Code, http.StatusOK)
	}
}

func TestRetryTransport_ExhaustedReturnsLastResponse(t *testing.T) {
	inner := &countingTransport{statuses: []int{503, 503, 503}}
	tr := retry.NewTransport(inner, globalCfg(true, 3, []int{503}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, noRouteRetry())

	if inner.calls != 3 {
		t.Errorf("calls = %d, want 3 (all attempts exhausted)", inner.calls)
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (last response written)", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestRetryTransport_NonRetryableStatusNotRetried(t *testing.T) {
	inner := &countingTransport{statuses: []int{http.StatusNotFound}}
	tr := retry.NewTransport(inner, globalCfg(true, 3, []int{502, 503, 504}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, noRouteRetry())

	if inner.calls != 1 {
		t.Errorf("calls = %d, want 1 (404 is not retryable)", inner.calls)
	}
}

func TestRetryTransport_PerRouteConfigOverridesGlobal(t *testing.T) {
	// Global says 3 attempts; per-route says 2.
	inner := &countingTransport{statuses: []int{502, 502, 200}}
	global := globalCfg(true, 3, []int{502})
	tr := retry.NewTransport(inner, global)

	routeWithOverride := &domain.Route{
		Name: "svc",
		Upstream: domain.UpstreamTarget{
			URL: "http://up",
			Retry: domain.RetryConfig{
				Enabled:          true,
				MaxAttempts:      2,
				InitialBackoffMs: 1,
				Multiplier:       1,
				RetryableStatus:  []int{502},
			},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, routeWithOverride)

	// With max 2 attempts: attempt 0 → 502 (retry), attempt 1 → 502 (exhausted).
	if inner.calls != 2 {
		t.Errorf("calls = %d, want 2 (per-route override max_attempts=2)", inner.calls)
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (last 502 written after exhaustion)", rr.Code, http.StatusBadGateway)
	}
}

func TestRetryTransport_ContextCancellationStopsRetries(t *testing.T) {
	inner := &countingTransport{statuses: []int{502, 502, 502}}
	tr := retry.NewTransport(inner, domain.RetryConfig{
		Enabled:          true,
		MaxAttempts:      3,
		InitialBackoffMs: 50, // non-trivial sleep so cancel can interrupt
		Multiplier:       1,
		RetryableStatus:  []int{502},
	})

	ctx, cancel := cancelAfter(30 * time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	_ = tr.Forward(rr, req, noRouteRetry())

	// At least one call must have been made; fewer than 3 because the context
	// was cancelled before the second backoff sleep expired.
	if inner.calls == 0 {
		t.Error("expected at least one attempt before cancel")
	}
	if inner.calls >= 3 {
		t.Errorf("expected fewer than 3 attempts due to context cancellation; got %d", inner.calls)
	}
}

// cancelAfter creates a context that cancels itself after d.
func cancelAfter(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
