// Package leakybucket implements the leaky bucket (reject-only) rate limiting algorithm.
// New requests are allowed as long as the virtual queue depth has not been reached.
// The queue drains at DrainRatePerSecond, so slots become available over time.
//
// This is the reject-only variant: when the queue is full the request is denied
// immediately with no waiting. The true queuing variant (which delays responses)
// requires a different port interface and is not implemented here.
//
// Concurrency: 16 independent shards reduce mutex contention under high cardinality.
// Stale entries are evicted by a background goroutine every minute.
//
// Drain arithmetic uses integer nanoseconds instead of float64 to avoid per-call
// floating-point conversions. drainNanosPerToken is pre-computed once in New().
package leakybucket

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

// RateLimiter is an in-memory leaky bucket (reject-only) rate limiter.
type RateLimiter struct {
	shards             [rlshard.NumShards]shard
	rule               domain.LeakyBucketRule
	drainNanosPerToken int64         // nanoseconds per drained token — pre-computed to avoid float64 per call
	evictTTL           time.Duration // max(rlshard.StaleEntryTTL, full-queue drain time) — pre-computed in New
}

type entry struct {
	// level is the integer number of requests currently in the virtual queue.
	level int
	// undrainedNs accumulates nanoseconds of elapsed time not yet converted to a
	// drained token. Replaces the float64 remainder field to keep all arithmetic integer.
	undrainedNs int64
	lastSeen    time.Time
}

// New creates a leaky bucket rate limiter with the given rule and starts a
// background eviction goroutine that exits when ctx is cancelled.
func New(ctx context.Context, rule domain.LeakyBucketRule) *RateLimiter {
	if rule.DrainRatePerSecond <= 0 {
		panic("leakybucket: DrainRatePerSecond must be > 0")
	}
	nanosPerToken := int64(float64(time.Second) / rule.DrainRatePerSecond)
	if nanosPerToken < 1 {
		nanosPerToken = 1 // guard against rates > 1e9 req/s truncating to zero
	}
	// Use the larger of the static TTL and the time to drain a fully-loaded queue.
	// A queue at maximum depth must not be evicted before it has had the opportunity
	// to drain, or the key's level would reset to zero — bypassing depth enforcement.
	drainDuration := time.Duration(float64(time.Second) * float64(rule.QueueDepth) / rule.DrainRatePerSecond)
	rl := &RateLimiter{
		rule:               rule,
		drainNanosPerToken: nanosPerToken,
		evictTTL:           max(rlshard.StaleEntryTTL, drainDuration),
	}
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

// Allow returns true if the virtual queue for key has capacity for one more request.
// Whole tokens that have drained since the last call are subtracted before the check.
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	sh := &rl.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	e, ok := sh.entries[key]
	if !ok {
		sh.entries[key] = &entry{level: 1, lastSeen: now}
		return true
	}

	// Compute how many whole tokens have drained since the last call using integer
	// nanosecond arithmetic — avoids float64 conversions and math.Floor on the hot path.
	elapsed := int64(now.Sub(e.lastSeen))
	e.lastSeen = now
	totalNs := e.undrainedNs + elapsed
	wholeTokens := int(totalNs / rl.drainNanosPerToken)
	e.undrainedNs = totalNs % rl.drainNanosPerToken

	e.level -= wholeTokens
	if e.level < 0 {
		e.level = 0
		// Do not zero undrainedNs — fractional progress toward the next drain is
		// real elapsed time and must carry forward so the effective drain rate matches
		// the configured DrainRatePerSecond even after a queue-empty event.
	}

	if e.level >= rl.rule.QueueDepth {
		return false
	}
	e.level++
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
	for i := range rlshard.NumShards {
		rl.evictShard(i, now)
	}
}

func (rl *RateLimiter) evictShard(i int, now time.Time) {
	sh := &rl.shards[i]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for key, e := range sh.entries {
		if now.Sub(e.lastSeen) > rl.evictTTL {
			delete(sh.entries, key)
		}
	}
}
