package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

const staleEntryTTL = 10 * time.Minute

// RateLimiter is an in-memory token bucket rate limiter keyed by client identifier.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*entry
	rule    domain.RateLimitRule
}

type entry struct {
	bucket   *domain.TokenBucket
	lastSeen time.Time
}

// NewRateLimiter creates a rate limiter with the given rule and starts
// a background goroutine that evicts stale entries. The goroutine exits
// when ctx is cancelled.
func NewRateLimiter(ctx context.Context, rule domain.RateLimitRule) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*entry),
		rule:    rule,
	}
	go rl.evictLoop(ctx)
	return rl
}

// Allow checks whether a request from the given key is permitted.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.buckets[key]
	if !ok {
		bucket := domain.NewTokenBucket(rl.rule, now)
		e = &entry{bucket: bucket, lastSeen: now}
		rl.buckets[key] = e
	}
	e.lastSeen = now
	return e.bucket.Allow(now)
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

	for key, e := range rl.buckets {
		if now.Sub(e.lastSeen) > staleEntryTTL {
			delete(rl.buckets, key)
		}
	}
}
