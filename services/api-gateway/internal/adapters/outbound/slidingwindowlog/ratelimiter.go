// Package slidingwindowlog implements the sliding-window log rate limiting algorithm.
// Every allowed request is timestamped. On each new request, entries older than
// WindowDuration are discarded before the count is compared to the limit.
//
// This is the most accurate algorithm — no boundary spike, no approximation.
// Memory cost is O(N requests within the window) per key; avoid it when
// RequestsPerWindow is very large.
//
// Concurrency: 16 independent shards reduce mutex contention under high cardinality.
// Per-key logs are compacted on every Allow call via binary search eviction, so
// in-window memory reclamation is free. A background goroutine (governed by ctx)
// fires every rlshard.EvictTick and removes keys whose entire log has expired, preventing
// unbounded growth from permanently silent clients. The eviction function itself
// is directly exercised by white-box tests in evict_test.go; the goroutine
// scheduling is an untested implementation detail.
package slidingwindowlog

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/rlshard"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*RateLimiter)(nil)

type shard struct {
	mu   sync.Mutex
	logs map[string][]time.Time
}

// RateLimiter is an in-memory sliding-window log rate limiter keyed by client identifier.
type RateLimiter struct {
	shards [rlshard.NumShards]shard
	rule   domain.SlidingWindowLogRule
}

// New creates a sliding-window log rate limiter with the given rule.
// ctx governs the background eviction goroutine; cancel it on shutdown.
func New(ctx context.Context, rule domain.SlidingWindowLogRule) *RateLimiter {
	rl := &RateLimiter{rule: rule}
	for i := range rlshard.NumShards {
		rl.shards[i].logs = make(map[string][]time.Time)
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

// Allow returns true if the number of requests from key within the sliding window
// is below the limit. Stale entries are evicted before the count is taken.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.rule.WindowDuration)

	sh := &rl.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	log := evict(sh.logs[key], cutoff)

	if len(log) >= rl.rule.RequestsPerWindow {
		sh.logs[key] = log
		return false
	}
	sh.logs[key] = append(log, now)
	return true
}

// evictLoop runs a periodic cleanup of keys whose entire log has slid out of
// the active window. It exits when ctx is cancelled.
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

// evictStale removes map entries whose entire log is outside the current window.
// A key is stale when all its timestamps predate the window cutoff, meaning no
// requests have been made from that key within the active window.
func (rl *RateLimiter) evictStale() {
	cutoff := time.Now().Add(-rl.rule.WindowDuration)
	for i := range rlshard.NumShards {
		rl.evictShard(i, cutoff)
	}
}

func (rl *RateLimiter) evictShard(i int, cutoff time.Time) {
	sh := &rl.shards[i]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for key, log := range sh.logs {
		trimmed := evict(log, cutoff)
		if len(trimmed) == 0 {
			delete(sh.logs, key)
		} else {
			sh.logs[key] = trimmed
		}
	}
}

// evict removes timestamps older than cutoff from a sorted log slice.
// Uses binary search so the scan is O(log N). When stale entries are found,
// the result is compacted into a new slice so the old backing array is eligible
// for garbage collection — preventing unbounded memory retention after a burst.
// Allow appends in monotonically increasing time order (serialised by mu), so
// the sort invariant required by sort.Search is always satisfied.
func evict(log []time.Time, cutoff time.Time) []time.Time {
	idx := sort.Search(len(log), func(i int) bool {
		return !log[i].Before(cutoff)
	})
	if idx == 0 {
		return log
	}
	compacted := make([]time.Time, len(log)-idx)
	copy(compacted, log[idx:])
	return compacted
}
