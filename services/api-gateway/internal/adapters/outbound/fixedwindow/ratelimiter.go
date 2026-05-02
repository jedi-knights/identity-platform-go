// Package fixedwindow implements the fixed-window counter rate limiting algorithm.
// Requests are counted in non-overlapping fixed-duration windows. Once the limit
// is reached, all further requests in that window are denied with no carry-over.
//
// Boundary spike: a client can burst 2× the limit at window boundaries by consuming
// the full quota at the end of one window and immediately at the start of the next.
// Use slidingwindowcounter or slidingwindowlog when this matters.
//
// Concurrency: 16 independent shards reduce mutex contention under high cardinality.
// Stale entries are evicted by a background goroutine every minute.
package fixedwindow

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/rlshard"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

type shard struct {
	mu      sync.Mutex
	entries map[string]*entry
}

// RateLimiter is an in-memory fixed-window counter rate limiter keyed by client identifier.
type RateLimiter struct {
	shards [rlshard.NumShards]shard
	rule   domain.FixedWindowRule
}

type entry struct {
	count       int
	windowStart time.Time
	lastSeen    time.Time
}

// New creates a fixed-window rate limiter with the given rule and starts a
// background eviction goroutine that exits when ctx is cancelled.
func New(ctx context.Context, rule domain.FixedWindowRule) *RateLimiter {
	rl := &RateLimiter{rule: rule}
	for i := range rlshard.NumShards {
		rl.shards[i].entries = make(map[string]*entry)
	}
	go rl.evictLoop(ctx)
	return rl
}

// shardIndex returns the shard index for key using inline FNV-1a.
// Inlined to avoid a hash.Hash interface allocation on every Allow call.
func shardIndex(key string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h % rlshard.NumShards
}

// Allow returns true if the request from key is within the current window's limit.
// Note: clients can burst 2× the limit at window boundaries by exhausting the quota
// at the end of one window and immediately at the start of the next; see package doc.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	sh := &rl.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e, ok := sh.entries[key]
	if !ok {
		sh.entries[key] = &entry{count: 1, windowStart: now, lastSeen: now}
		return true
	}
	e.lastSeen = now
	if now.Sub(e.windowStart) >= rl.rule.WindowDuration {
		e.count = 1
		e.windowStart = now
		return true
	}
	if e.count >= rl.rule.RequestsPerWindow {
		return false
	}
	e.count++
	return true
}

func (rl *RateLimiter) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(rlshard.EvictTick)
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
	// Use the larger of the static TTL and the window duration so that entries
	// whose window is still active (e.g. a 1-hour window) are never evicted early.
	ttl := max(rlshard.StaleEntryTTL, rl.rule.WindowDuration)
	for i := range rlshard.NumShards {
		rl.evictShard(i, now, ttl)
	}
}

func (rl *RateLimiter) evictShard(i int, now time.Time, ttl time.Duration) {
	sh := &rl.shards[i]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for key, e := range sh.entries {
		if now.Sub(e.lastSeen) > ttl {
			delete(sh.entries, key)
		}
	}
}
