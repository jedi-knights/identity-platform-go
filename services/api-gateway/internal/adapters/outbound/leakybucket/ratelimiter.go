// Package leakybucket implements the leaky bucket (reject-only) rate limiting algorithm.
// New requests are allowed as long as the virtual queue depth has not been reached.
// The queue drains at DrainRatePerSecond, so slots become available over time.
//
// This is the reject-only variant: when the queue is full the request is denied
// immediately with no waiting. The true queuing variant (which delays responses)
// requires a different port interface and is not implemented here.
package leakybucket

import (
	"math"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

// RateLimiter is an in-memory leaky bucket (reject-only) rate limiter.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	rule    domain.LeakyBucketRule
}

type entry struct {
	// level is the integer number of requests currently in the virtual queue.
	// Fractional drain progress is tracked separately in remainder so that
	// sub-token elapsed time is not lost between requests.
	level     int
	remainder float64 // fractional drain tokens accumulated since last drain
	lastSeen  time.Time
}

// New creates a leaky bucket rate limiter with the given rule.
func New(rule domain.LeakyBucketRule) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*entry),
		rule:    rule,
	}
}

// Allow returns true if the virtual queue for key has capacity for one more request.
// Whole tokens that have drained since the last call are subtracted before the check.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[key]
	if !ok {
		rl.entries[key] = &entry{level: 1, lastSeen: now}
		return true
	}

	// Compute how many whole tokens have drained since the last call.
	elapsed := now.Sub(e.lastSeen).Seconds()
	e.lastSeen = now
	drained := e.remainder + elapsed*rl.rule.DrainRatePerSecond
	wholeTokens := int(math.Floor(drained))
	e.remainder = drained - float64(wholeTokens)

	e.level -= wholeTokens
	if e.level < 0 {
		e.level = 0
		e.remainder = 0
	}

	if e.level >= rl.rule.QueueDepth {
		return false
	}
	e.level++
	return true
}
