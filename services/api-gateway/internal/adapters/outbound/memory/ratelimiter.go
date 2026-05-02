package memory

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

const staleEntryTTL = 10 * time.Minute

// RateLimiter is an in-memory token bucket rate limiter keyed by client identifier.
//
// Design: Strategy pattern — RateLimiter implements ports.RateLimiter so the
// container can swap it for any other strategy (e.g. Redis-backed) without
// changing the caller. The token bucket algorithm is provided by
// golang.org/x/time/rate, which is stdlib-backed and goroutine-safe, replacing
// the previous hand-rolled domain.TokenBucket.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limitEntry
	rule     domain.RateLimitRule
}

type limitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a rate limiter with the given rule and starts
// a background goroutine that evicts stale entries. The goroutine exits
// when ctx is cancelled.
func NewRateLimiter(ctx context.Context, rule domain.RateLimitRule) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*limitEntry),
		rule:     rule,
	}
	go rl.evictLoop(ctx)
	return rl
}

// Allow checks whether a request from the given key is permitted.
// Each unique key gets its own rate.Limiter created lazily on first use.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.limiters[key]
	if !ok {
		e = &limitEntry{
			limiter: rate.NewLimiter(
				rate.Limit(rl.rule.RequestsPerSecond),
				rl.rule.BurstSize,
			),
			lastSeen: now,
		}
		rl.limiters[key] = e
	}
	e.lastSeen = now
	return e.limiter.Allow()
}

// evictLoop periodically removes entries that have not been seen recently.
// It exits when ctx is cancelled.
func (rl *RateLimiter) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.evictStale()
		}
	}
}

func (rl *RateLimiter) evictStale() {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for key, e := range rl.limiters {
		if now.Sub(e.lastSeen) > staleEntryTTL {
			delete(rl.limiters, key)
		}
	}
}
