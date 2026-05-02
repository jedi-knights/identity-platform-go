//go:build unit

package circuitbreaker_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/circuitbreaker"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// cbConfig returns a CircuitBreakerConfig suitable for testing.
// The min-sample threshold of 5 in the ReadyToTrip function means we need
// to send at least 5 failing requests before the circuit opens.
func cbConfig() config.CircuitBreakerConfig {
	return config.CircuitBreakerConfig{
		Enabled:      true,
		MaxRequests:  1,
		IntervalSecs: 60,
		TimeoutSecs:  30,
		FailureRatio: 0.6,
	}
}

func route(name string) *domain.Route {
	return &domain.Route{Name: name}
}

// --- Compile-time interface check ---

func TestTransport_ImplementsUpstreamTransport(t *testing.T) {
	var _ ports.UpstreamTransport = circuitbreaker.NewTransport(
		&stubTransport{},
		cbConfig(),
	)
}

// --- Success path ---

// TestTransport_Forward_DelegatesSuccessToInner checks that a successful
// forward is passed through untouched when the circuit is closed.
func TestTransport_Forward_DelegatesSuccessToInner(t *testing.T) {
	inner := &stubTransport{code: http.StatusOK}
	tr := circuitbreaker.NewTransport(inner, cbConfig())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	err := tr.Forward(rr, req, route("svc"))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
}

// --- Circuit opens after threshold ---

// TestTransport_Forward_CircuitOpensAfterThreshold drives enough failures
// through the circuit to open it, then verifies that subsequent requests are
// rejected with 503 without reaching the inner transport.
func TestTransport_Forward_CircuitOpensAfterThreshold(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always return 200 so the test controls failure via the inner stub, not the HTTP status.
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	inner := &stubTransport{err: errors.New("upstream unreachable")}
	tr := circuitbreaker.NewTransport(inner, cbConfig())

	// Send 10 failing requests to exceed the minimum sample (5) and the 60% ratio.
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		_ = tr.Forward(rr, req, route("svc"))
	}

	// Now the circuit should be open — this request must be rejected with 503
	// and the inner transport must not be called.
	callsBefore := inner.calls
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	err := tr.Forward(rr, req, route("svc"))

	if err == nil {
		t.Fatal("expected error when circuit is open, got nil")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("open circuit: got status %d, want 503", rr.Code)
	}
	if inner.calls != callsBefore {
		t.Errorf("inner transport was called %d times with open circuit; want 0", inner.calls-callsBefore)
	}
}

// --- Per-route isolation ---

// TestTransport_Forward_BreakersArePerRoute verifies that failures on one route
// do not open the circuit for a different route. Each route gets its own breaker.
func TestTransport_Forward_BreakersArePerRoute(t *testing.T) {
	inner := &stubTransport{err: errors.New("upstream down")}
	tr := circuitbreaker.NewTransport(inner, cbConfig())

	// Trip the circuit for "route-a".
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		_ = tr.Forward(rr, req, route("route-a"))
	}

	// "route-b" should still have its circuit closed and reach the inner transport.
	// The inner transport will return an error, but the response should be the
	// inner stub's response (not a 503 from the breaker).
	inner.err = nil
	inner.code = http.StatusOK
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	err := tr.Forward(rr, req, route("route-b"))

	if err != nil {
		t.Fatalf("route-b: unexpected error %v — circuit should be closed for this route", err)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("route-b: got status %d, want %d", rr.Code, http.StatusOK)
	}
}

// --- stubTransport ---

// stubTransport is a test double for ports.UpstreamTransport.
type stubTransport struct {
	code  int
	err   error
	calls int
}

var _ ports.UpstreamTransport = (*stubTransport)(nil)

func (s *stubTransport) Forward(w http.ResponseWriter, _ *http.Request, _ *domain.Route) error {
	s.calls++
	if s.err != nil {
		http.Error(w, s.err.Error(), http.StatusBadGateway)
		return s.err
	}
	w.WriteHeader(s.code)
	return nil
}
