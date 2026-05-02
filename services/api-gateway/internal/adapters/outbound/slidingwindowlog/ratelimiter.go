// Package slidingwindowlog implements the sliding-window log rate limiting algorithm.
// Every allowed request is timestamped. On each new request, entries older than
// WindowDuration are discarded before the count is compared to the limit.
//
// This is the most accurate algorithm — no boundary spike, no approximation.
// Memory cost is O(N requests within the window) per key; avoid it when
// RequestsPerWindow is very large.
package slidingwindowlog

import (
	"sort"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

// RateLimiter is an in-memory sliding-window log rate limiter keyed by client identifier.
type RateLimiter struct {
	mu   sync.Mutex
	logs map[string][]time.Time
	rule domain.SlidingWindowLogRule
}

// New creates a sliding-window log rate limiter with the given rule.
func New(rule domain.SlidingWindowLogRule) *RateLimiter {
	return &RateLimiter{
		logs: make(map[string][]time.Time),
		rule: rule,
	}
}

// Allow returns true if the number of requests from key within the sliding window
// is below the limit. Stale entries are evicted before the count is taken.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.rule.WindowDuration)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	log := rl.evict(rl.logs[key], cutoff)

	if len(log) >= rl.rule.RequestsPerWindow {
		rl.logs[key] = log
		return false
	}
	rl.logs[key] = append(log, now)
	return true
}

// evict removes timestamps older than cutoff from a sorted log slice.
// Uses binary search so eviction is O(log N) rather than O(N).
func (rl *RateLimiter) evict(log []time.Time, cutoff time.Time) []time.Time {
	idx := sort.Search(len(log), func(i int) bool {
		return !log[i].Before(cutoff)
	})
	return log[idx:]
}
