// Package roundrobin provides a round-robin URL picker and a transport decorator
// that distributes requests across a pool of upstream endpoints.
//
// Design: Strategy pattern — Picker implements ports.URLPicker so the selection
// algorithm can be swapped (e.g. weighted round-robin, random, least-connections)
// without changing the Transport decorator or any other caller.
package roundrobin

import (
	"sync"
	"sync/atomic"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Picker must satisfy ports.URLPicker.
var _ ports.URLPicker = (*Picker)(nil)

// Picker implements ports.URLPicker using an atomic counter per route name.
//
// Each route gets its own counter stored in a sync.Map. The counter is an
// *atomic.Uint64 so increment and read are lock-free on the fast path —
// only the first request to a new route acquires a write lock to insert the
// counter into the map.
type Picker struct {
	counters sync.Map // map[string]*atomic.Uint64
}

// NewPicker creates a Picker with no pre-allocated counters.
// Counters are created lazily on the first Pick call for each route.
func NewPicker() *Picker {
	return &Picker{}
}

// Pick returns the next URL from urls for the given route in round-robin order.
// It is safe to call from multiple goroutines concurrently.
//
// If urls is empty Pick returns an empty string; callers should guard against
// this case (the config validator ensures pools are non-empty in practice).
func (p *Picker) Pick(routeName string, urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	// Fast path: counter already exists.
	if v, ok := p.counters.Load(routeName); ok {
		n := v.(*atomic.Uint64).Add(1) - 1
		return urls[n%uint64(len(urls))]
	}
	// Slow path: first request for this route — insert a new counter.
	// LoadOrStore is atomic; if two goroutines race here only one counter wins.
	counter := new(atomic.Uint64)
	actual, _ := p.counters.LoadOrStore(routeName, counter)
	n := actual.(*atomic.Uint64).Add(1) - 1
	return urls[n%uint64(len(urls))]
}
