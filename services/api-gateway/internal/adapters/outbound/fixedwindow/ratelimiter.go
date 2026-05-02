// Package fixedwindow implements the fixed-window counter rate limiting algorithm.
// Requests are counted in non-overlapping fixed-duration windows. Once the limit
// is reached, all further requests in that window are denied with no carry-over.
//
// Boundary spike: a client can burst 2× the limit at window boundaries by consuming
// the full quota at the end of one window and immediately at the start of the next.
// Use slidingwindowcounter or slidingwindowlog when this matters.
package fixedwindow

import (
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

// RateLimiter is an in-memory fixed-window counter rate limiter keyed by client identifier.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	rule    domain.FixedWindowRule
}

type entry struct {
	count       int
	windowStart time.Time
}

// New creates a fixed-window rate limiter with the given rule.
func New(rule domain.FixedWindowRule) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*entry),
		rule:    rule,
	}
}

// Allow returns true if the request from key is within the current window's limit.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[key]
	if !ok || now.Sub(e.windowStart) >= rl.rule.WindowDuration {
		rl.entries[key] = &entry{count: 1, windowStart: now}
		return true
	}
	if e.count >= rl.rule.RequestsPerWindow {
		return false
	}
	e.count++
	return true
}
