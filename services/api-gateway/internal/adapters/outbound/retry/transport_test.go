//go:build unit

package retry_test

import (
	"context"
	"errors"
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

// errorTransport returns a transport-level error without writing any status code.
type errorTransport struct{ calls int }

func (e *errorTransport) Forward(_ http.ResponseWriter, _ *http.Request, _ *domain.Route) error {
	e.calls++
	return errors.New("dial tcp: connection refused")
}

var _ ports.UpstreamTransport = (*errorTransport)(nil)

// bodyTransport writes a response status and a fixed body payload.
type bodyTransport struct{ body string }

func (b *bodyTransport) Forward(w http.ResponseWriter, _ *http.Request, _ *domain.Route) error {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.body))
	return nil
}

var _ ports.UpstreamTransport = (*bodyTransport)(nil)

// failWriter is an http.ResponseWriter whose Write always returns an error,
// used to exercise the io.Copy error path in copyRecorder.
type failWriter struct{ header http.Header }

func (f *failWriter) Header() http.Header       { return f.header }
func (f *failWriter) WriteHeader(int)            {}
func (f *failWriter) Write([]byte) (int, error)  { return 0, errors.New("write: broken pipe") }

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
	if err := tr.Forward(rr, req, noRouteRetry()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inner.calls != 1 {
		t.Errorf("calls = %d, want 1 (disabled retry must not retry)", inner.calls)
	}
}

func TestRetryTransport_PassthroughWhenMaxAttemptsOne(t *testing.T) {
	inner := &countingTransport{statuses: []int{http.StatusBadGateway}}
	tr := retry.NewTransport(inner, globalCfg(true, 1, []int{502}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := tr.Forward(rr, req, noRouteRetry()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inner.calls != 1 {
		t.Errorf("calls = %d, want 1 (max_attempts=1 means no retry)", inner.calls)
	}
}

func TestRetryTransport_SuccessOnFirstAttemptNoRetry(t *testing.T) {
	inner := &countingTransport{statuses: []int{http.StatusOK}}
	tr := retry.NewTransport(inner, globalCfg(true, 3, []int{502, 503, 504}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := tr.Forward(rr, req, noRouteRetry()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if err := tr.Forward(rr, req, noRouteRetry()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if err := tr.Forward(rr, req, noRouteRetry()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if err := tr.Forward(rr, req, noRouteRetry()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if err := tr.Forward(rr, req, routeWithOverride); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if err := tr.Forward(rr, req, noRouteRetry()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// At least one call must have been made; fewer than 3 because the context
	// was cancelled before the second backoff sleep expired.
	if inner.calls == 0 {
		t.Error("expected at least one attempt before cancel")
	}
	if inner.calls >= 3 {
		t.Errorf("expected fewer than 3 attempts due to context cancellation; got %d", inner.calls)
	}
}

func TestRetryTransport_RetriesOnTransportError(t *testing.T) {
	// inner returns a transport-level error without writing any status code.
	// The retry transport must treat this as retryable — not as a 200 success.
	inner := &errorTransport{}
	tr := retry.NewTransport(inner, globalCfg(true, 3, []int{502, 503}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	err := tr.Forward(rr, req, noRouteRetry())

	if inner.calls != 3 {
		t.Errorf("calls = %d, want 3 (transport error must trigger retries)", inner.calls)
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (exhausted transport errors must write 502)", rr.Code, http.StatusBadGateway)
	}
	if err == nil {
		t.Error("expected non-nil error when all attempts fail with transport error")
	}
}

func TestRetryTransport_CopyErrorPropagated(t *testing.T) {
	// When the response body copy to the real writer fails (e.g. client disconnect),
	// the error must be returned to the caller, not silently discarded.
	// MaxAttempts=2 is the minimum to exercise retryForward (<=1 bypasses it).
	inner := &bodyTransport{body: "hello"}
	tr := retry.NewTransport(inner, globalCfg(true, 2, []int{502}))

	w := &failWriter{header: http.Header{}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	err := tr.Forward(w, req, noRouteRetry())
	if err == nil {
		t.Error("expected non-nil error when the response body copy fails")
	}
}

// cancelAfter creates a context that cancels itself after d.
func cancelAfter(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
