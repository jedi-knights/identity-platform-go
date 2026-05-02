// Package circuitbreaker is the outbound adapter that wraps an UpstreamTransport
// with per-route circuit breaking via sony/gobreaker.
//
// Design: Decorator pattern — Transport implements the same ports.UpstreamTransport
// interface as the inner transport it wraps. Callers cannot distinguish a plain
// proxy.Transport from a circuit-breaking one; behaviour is added transparently.
//
// The circuit breaker state machine (Closed → Open → Half-Open) is managed by
// gobreaker independently for each route. When the circuit is Open, requests are
// rejected with 503 Service Unavailable without reaching the upstream at all —
// giving the upstream time to recover while protecting the system from cascading
// failures.
package circuitbreaker

import (
	"net/http"
	"sync"
	"time"

	"github.com/sony/gobreaker"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Transport must satisfy ports.UpstreamTransport.
var _ ports.UpstreamTransport = (*Transport)(nil)

// Transport wraps an inner UpstreamTransport and adds per-route circuit breaking.
type Transport struct {
	inner    ports.UpstreamTransport
	cfg      config.CircuitBreakerConfig
	mu       sync.Mutex
	breakers map[string]*gobreaker.CircuitBreaker
}

// NewTransport creates a circuit-breaking decorator around inner.
// One gobreaker.CircuitBreaker is created lazily per route name on first use.
func NewTransport(inner ports.UpstreamTransport, cfg config.CircuitBreakerConfig) *Transport {
	return &Transport{
		inner:    inner,
		cfg:      cfg,
		breakers: make(map[string]*gobreaker.CircuitBreaker),
	}
}

// Forward forwards the request through the circuit breaker for route.Name.
//
//   - Closed state: the request is delegated to the inner transport normally.
//     If inner returns an error the failure counter increments.
//   - Open state: the request is rejected immediately with 503; inner is not called.
//   - Half-Open state: up to cfg.MaxRequests probe requests are forwarded.
//     Success closes the circuit; failure re-opens it.
func (t *Transport) Forward(w http.ResponseWriter, r *http.Request, route *domain.Route) error {
	cb := t.breakerFor(route.Name)

	// cb.Execute runs our function only when the circuit is Closed or Half-Open.
	// When Open it returns gobreaker.ErrOpenState without calling our function,
	// so no response has been written to w yet — we must write 503 ourselves.
	_, err := cb.Execute(func() (interface{}, error) {
		return nil, t.inner.Forward(w, r, route)
	})

	switch err {
	case nil:
		return nil
	case gobreaker.ErrOpenState, gobreaker.ErrTooManyRequests:
		// Circuit is open (or half-open quota exhausted); upstream not called.
		// inner has not written anything to w, so we are safe to write 503.
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return err
	default:
		// Upstream was reachable but returned an error (e.g. 502).
		// inner.Forward has already written the error response to w.
		return err
	}
}

// breakerFor returns the circuit breaker for the given route name, creating it
// lazily if this is the first request to that route.
func (t *Transport) breakerFor(routeName string) *gobreaker.CircuitBreaker {
	t.mu.Lock()
	defer t.mu.Unlock()

	if cb, ok := t.breakers[routeName]; ok {
		return cb
	}

	settings := gobreaker.Settings{
		Name:        routeName,
		MaxRequests: t.cfg.MaxRequests,
		Interval:    time.Duration(t.cfg.IntervalSecs) * time.Second,
		Timeout:     time.Duration(t.cfg.TimeoutSecs) * time.Second,
		// ReadyToTrip opens the circuit when the failure ratio exceeds the threshold.
		// gobreaker.Counts tracks requests, successes, failures, consecutive failures,
		// and consecutive successes within the current counting interval.
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			if counts.Requests < 5 {
				// Require a minimum sample size before making a trip decision.
				// This prevents a single cold-start failure from opening the circuit.
				return false
			}
			ratio := float64(counts.TotalFailures) / float64(counts.Requests)
			return ratio >= t.cfg.FailureRatio
		},
	}

	cb := gobreaker.NewCircuitBreaker(settings)
	t.breakers[routeName] = cb
	return cb
}
