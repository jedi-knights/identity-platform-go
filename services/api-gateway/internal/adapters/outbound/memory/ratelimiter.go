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

const (
	numRateLimiterShards = 16
	staleEntryTTL        = 10 * time.Minute
)

type rateShard struct {
	mu       sync.Mutex
	limiters map[string]*limitEntry
}

// RateLimiter is an in-memory token bucket rate limiter keyed by client identifier.
//
// Design: Strategy pattern — RateLimiter implements ports.RateLimiter so the
// container can swap it for any other strategy (e.g. Redis-backed) without
// changing the caller. The token bucket algorithm is provided by
// golang.org/x/time/rate, which is stdlib-backed and goroutine-safe, replacing
// the previous hand-rolled domain.TokenBucket.
//
// Concurrency: 16 independent shards reduce mutex contention under high cardinality.
type RateLimiter struct {
	shards [numRateLimiterShards]rateShard
	rule   domain.RateLimitRule
}

type limitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a rate limiter with the given rule and starts
// a background goroutine that evicts stale entries. The goroutine exits
// when ctx is cancelled.
func NewRateLimiter(ctx context.Context, rule domain.RateLimitRule) *RateLimiter {
	rl := &RateLimiter{rule: rule}
	for i := range numRateLimiterShards {
		rl.shards[i].limiters = make(map[string]*limitEntry)
	}
	go rl.evictLoop(ctx)
	return rl
}

// rateLimiterShardIndex returns the shard index for key using inline FNV-1a.
// Inlined to avoid a hash.Hash interface allocation on every Allow call.
func rateLimiterShardIndex(key string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h % numRateLimiterShards
}

// Allow checks whether a request from the given key is permitted.
// Each unique key gets its own rate.Limiter created lazily on first use.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	sh := &rl.shards[rateLimiterShardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e, ok := sh.limiters[key]
	if !ok {
		e = &limitEntry{
			limiter: rate.NewLimiter(
				rate.Limit(rl.rule.RequestsPerSecond),
				rl.rule.BurstSize,
			),
			lastSeen: now,
		}
		sh.limiters[key] = e
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
	for i := range numRateLimiterShards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		for key, e := range sh.limiters {
			if now.Sub(e.lastSeen) > staleEntryTTL {
				delete(sh.limiters, key)
			}
		}
		sh.mu.Unlock()
	}
}
