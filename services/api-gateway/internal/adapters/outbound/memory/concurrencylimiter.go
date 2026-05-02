package memory

import (
	"sync"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.ConcurrencyLimiter = (*ConcurrencyLimiter)(nil)

// ConcurrencyLimiter is an in-memory concurrency limiter keyed by client identifier.
// It counts simultaneous in-flight requests per key and denies new requests once
// MaxInFlight slots are taken. Callers must call Release after each successful Acquire.
type ConcurrencyLimiter struct {
	mu       sync.Mutex
	inflight map[string]int
	rule     domain.ConcurrencyRule
}

// NewConcurrencyLimiter creates a concurrency limiter with the given rule.
func NewConcurrencyLimiter(rule domain.ConcurrencyRule) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		inflight: make(map[string]int),
		rule:     rule,
	}
}

// Acquire reserves a concurrency slot for key. Returns true if a slot was available.
// The caller must call Release exactly once per successful Acquire.
func (cl *ConcurrencyLimiter) Acquire(key string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.inflight[key] >= cl.rule.MaxInFlight {
		return false
	}
	cl.inflight[key]++
	return true
}

// Release frees a slot previously reserved by Acquire.
// A spurious Release (without a preceding Acquire) is a no-op.
func (cl *ConcurrencyLimiter) Release(key string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.inflight[key] > 0 {
		cl.inflight[key]--
	}
}
