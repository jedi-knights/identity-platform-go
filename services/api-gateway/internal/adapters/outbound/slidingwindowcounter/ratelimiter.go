// Package slidingwindowcounter implements the sliding-window counter rate limiting
// algorithm. It maintains two consecutive fixed-window counts (previous and current)
// and estimates the in-window request count by linear interpolation:
//
//	estimate = prev_count × (1 − elapsed/window) + curr_count
//
// This eliminates the boundary spike of the fixed-window algorithm with O(1) memory
// per key. Approximation error is empirically < 0.003% (Cloudflare analysis).
//
// Concurrency: 16 independent shards reduce mutex contention under high cardinality.
// Stale entries are evicted by a background goroutine every minute.
package slidingwindowcounter

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

// RateLimiter is an in-memory sliding-window counter rate limiter.
type RateLimiter struct {
	shards     [rlshard.NumShards]shard
	rule       domain.SlidingWindowCounterRule
	windowSecs float64 // rule.WindowDuration.Seconds() — pre-computed to avoid division per Allow call
}

type entry struct {
	prevCount   int
	currCount   int
	windowStart time.Time
	lastSeen    time.Time
}

// New creates a sliding-window counter rate limiter with the given rule and starts
// a background eviction goroutine that exits when ctx is cancelled.
func New(ctx context.Context, rule domain.SlidingWindowCounterRule) *RateLimiter {
	if rule.WindowDuration <= 0 {
		panic("slidingwindowcounter: WindowDuration must be > 0")
	}
	rl := &RateLimiter{rule: rule, windowSecs: rule.WindowDuration.Seconds()}
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

// Allow returns true if the estimated in-window request count for key is below
// the limit. Window roll-overs are handled lazily on each Allow call.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	sh := &rl.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e, ok := sh.entries[key]
	if !ok {
		sh.entries[key] = &entry{currCount: 1, windowStart: now, lastSeen: now}
		return true
	}
	e.lastSeen = now

	elapsed := now.Sub(e.windowStart)

	switch {
	case elapsed >= 2*rl.rule.WindowDuration:
		// Both windows fully expired — reset in place to avoid an extra allocation.
		e.prevCount = 0
		e.currCount = 1
		e.windowStart = now
		return true

	case elapsed >= rl.rule.WindowDuration:
		// Current window has expired; roll it forward.
		e.prevCount = e.currCount
		e.currCount = 0
		e.windowStart = e.windowStart.Add(rl.rule.WindowDuration)
		elapsed = now.Sub(e.windowStart)
	}

	// Estimate: how much of the previous window still overlaps with the current window.
	fraction := 1.0 - elapsed.Seconds()/rl.windowSecs
	estimate := float64(e.prevCount)*fraction + float64(e.currCount)

	if estimate >= float64(rl.rule.RequestsPerWindow) {
		return false
	}
	e.currCount++
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
