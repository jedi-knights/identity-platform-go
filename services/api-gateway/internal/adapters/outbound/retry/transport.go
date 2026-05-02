// Package retry is the outbound adapter that adds exponential-backoff retry
// behaviour to any ports.UpstreamTransport.
//
// Design: Decorator pattern — Transport wraps an inner UpstreamTransport and
// intercepts Forward calls to retry on transient upstream errors. Each attempt
// is buffered in a fresh httptest.ResponseRecorder so the real http.ResponseWriter
// is only written once — on the first successful attempt or after exhausting all
// retries. The inner transport (roundrobin or weighted) is called on every attempt,
// so each retry may land on a different upstream when load balancing is active.
package retry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// recorderPool reuses ResponseRecorder allocations across retry attempts.
// Each get resets Code, HeaderMap, and Body so the recorder is clean for reuse.
var recorderPool = sync.Pool{
	New: func() any { return httptest.NewRecorder() },
}

// Compile-time check: Transport must satisfy ports.UpstreamTransport.
var _ ports.UpstreamTransport = (*Transport)(nil)

// Transport wraps an inner UpstreamTransport with exponential-backoff retry logic.
//
// The global retry config is used unless the route carries a per-route override
// (route.Upstream.Retry.Enabled == true && MaxAttempts > 0). Per-route config
// is mapped from domain.RetryConfig at route resolution time, matching the same
// field set as the global config.
//
// Request bodies: retry-with-body is a known limitation. After the first attempt
// the request body is exhausted; subsequent retries send an empty body. This is
// acceptable for the primary retry use-case: GET requests to idempotent endpoints
// that fail with 502/503/504 before the upstream reads the body.
type Transport struct {
	inner  ports.UpstreamTransport
	global domain.RetryConfig
}

// NewTransport wraps inner with retry-backoff behaviour governed by globalCfg.
func NewTransport(inner ports.UpstreamTransport, globalCfg domain.RetryConfig) *Transport {
	return &Transport{inner: inner, global: globalCfg}
}

// Forward proxies the request through the inner transport with optional retries.
// When retries are disabled or MaxAttempts ≤ 1, it delegates directly to avoid overhead.
func (t *Transport) Forward(w http.ResponseWriter, r *http.Request, route *domain.Route) error {
	cfg := t.resolveConfig(route)
	if !cfg.Enabled || cfg.MaxAttempts <= 1 {
		return t.inner.Forward(w, r, route)
	}
	return t.retryForward(w, r, route, cfg)
}

// resolveConfig returns the per-route config when it is active (Enabled + MaxAttempts > 0),
// otherwise the global config supplied at construction.
func (t *Transport) resolveConfig(route *domain.Route) domain.RetryConfig {
	rc := route.Upstream.Retry
	if rc.Enabled && rc.MaxAttempts > 0 {
		return rc
	}
	return t.global
}

func (t *Transport) retryForward(w http.ResponseWriter, r *http.Request, route *domain.Route, cfg domain.RetryConfig) error {
	retryable := makeRetryableSet(cfg.RetryableStatus)
	bo := newExponentialBackoff(cfg)

	// lastRec is always set: attempt 0 always runs (sleepContext is skipped when
	// attempt == 0), so the post-loop copy/put never operates on nil.
	var lastRec *httptest.ResponseRecorder
	var lastFwdErr error
	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if attempt > 0 && !sleepContext(r.Context(), bo.NextBackOff()) {
			break
		}
		rec := acquireRecorder()
		fwdErr := t.inner.Forward(rec, r, route)
		if lastRec != nil {
			recorderPool.Put(lastRec)
		}
		lastRec = rec
		lastFwdErr = fwdErr
		if !shouldRetry(fwdErr, rec.Code, retryable) {
			break
		}
	}
	// When all attempts fail with a transport error the recorder holds the default
	// 200 status (nothing was written to it). Overwrite with 502 so the caller
	// receives a proper gateway-error response, consistent with proxy.Transport.
	if lastFwdErr != nil {
		lastRec.Code = http.StatusBadGateway
	}
	copyErr := copyRecorder(w, lastRec)
	recorderPool.Put(lastRec)
	// errors.Join returns nil when both are nil (success path) and preserves both
	// errors for errors.Is/As inspection when the upstream and write both fail.
	return errors.Join(lastFwdErr, copyErr)
}

// shouldRetry reports whether the retry loop should continue after an attempt.
// A transport-level error always warrants a retry; otherwise the status code is
// checked against the configured retryable set.
func shouldRetry(fwdErr error, code int, retryable map[int]bool) bool {
	return fwdErr != nil || retryable[code]
}

// acquireRecorder gets a ResponseRecorder from the pool and resets all fields
// (including unexported ones) via struct-level assignment so wroteHeader is zeroed.
func acquireRecorder() *httptest.ResponseRecorder {
	rec := recorderPool.Get().(*httptest.ResponseRecorder)
	buf := rec.Body
	*rec = httptest.ResponseRecorder{Body: buf, Code: http.StatusOK}
	buf.Reset()
	return rec
}

// makeRetryableSet converts a status-code slice to a set for O(1) lookup.
func makeRetryableSet(statuses []int) map[int]bool {
	s := make(map[int]bool, len(statuses))
	for _, code := range statuses {
		s[code] = true
	}
	return s
}

// newExponentialBackoff builds a configured ExponentialBackOff.
// In backoff v5, ExponentialBackOff has no MaxElapsedTime; the attempt-count
// loop in retryForward is the sole termination mechanism.
// Reset() must be called before first use to initialise currentInterval.
func newExponentialBackoff(cfg domain.RetryConfig) *backoff.ExponentialBackOff {
	bo := backoff.NewExponentialBackOff()
	if cfg.InitialBackoffMs > 0 {
		bo.InitialInterval = time.Duration(cfg.InitialBackoffMs) * time.Millisecond
	}
	if cfg.Multiplier > 0 {
		bo.Multiplier = cfg.Multiplier
	}
	bo.Reset()
	return bo
}

// sleepContext sleeps for d, returning false if the context is cancelled first.
// Returns false immediately for d ≤ 0 (backoff.Stop sentinel or zero interval).
func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return false
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// copyRecorder writes the recorder's status, headers, and body to the real writer.
// Returns the error from io.Copy so callers can detect client disconnects.
func copyRecorder(w http.ResponseWriter, rec *httptest.ResponseRecorder) error {
	for k, vs := range rec.Header() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, err := io.Copy(w, rec.Body)
	return err
}
