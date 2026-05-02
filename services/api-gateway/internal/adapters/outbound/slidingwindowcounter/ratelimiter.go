// Package slidingwindowcounter implements the sliding-window counter rate limiting
// algorithm. It maintains two consecutive fixed-window counts (previous and current)
// and estimates the in-window request count by linear interpolation:
//
//	estimate = prev_count × (1 − elapsed/window) + curr_count
//
// This eliminates the boundary spike of the fixed-window algorithm with O(1) memory
// per key. Approximation error is empirically < 0.003% (Cloudflare analysis).
package slidingwindowcounter

import (
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

// RateLimiter is an in-memory sliding-window counter rate limiter.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	rule    domain.SlidingWindowCounterRule
}

type entry struct {
	prevCount   int
	currCount   int
	windowStart time.Time
}

// New creates a sliding-window counter rate limiter with the given rule.
func New(rule domain.SlidingWindowCounterRule) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*entry),
		rule:    rule,
	}
}

// Allow returns true if the estimated in-window request count for key is below
// the limit. Window roll-overs are handled lazily on each Allow call.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[key]
	if !ok {
		rl.entries[key] = &entry{currCount: 1, windowStart: now}
		return true
	}

	elapsed := now.Sub(e.windowStart)

	switch {
	case elapsed >= 2*rl.rule.WindowDuration:
		// Both previous and current windows are fully expired.
		rl.entries[key] = &entry{currCount: 1, windowStart: now}
		return true

	case elapsed >= rl.rule.WindowDuration:
		// Current window has expired; roll it forward.
		e.prevCount = e.currCount
		e.currCount = 0
		e.windowStart = e.windowStart.Add(rl.rule.WindowDuration)
		elapsed = now.Sub(e.windowStart)
	}

	// Estimate: how much of the previous window still overlaps with the current window.
	fraction := 1.0 - elapsed.Seconds()/rl.rule.WindowDuration.Seconds()
	estimate := float64(e.prevCount)*fraction + float64(e.currCount)

	if estimate >= float64(rl.rule.RequestsPerWindow) {
		return false
	}
	e.currCount++
	return true
}
