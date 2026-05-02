//go:build unit

package leakybucket

// White-box tests that access unexported fields and methods to verify eviction
// TTL correctness. These cannot be written as black-box tests because evoking
// a stale-entry eviction requires calling evictShard with a synthetic future
// time, which is only possible with internal access.

import (
	"context"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/rlshard"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// TestLeakyBucket_EvictTTLAccountsForDrainDuration verifies that evictShard
// uses evictTTL (which is max(rlshard.StaleEntryTTL, fullQueueDrainDuration)) rather
// than the bare rlshard.StaleEntryTTL constant. Without this, entries can be evicted
// while still holding queue-level state, allowing clients to bypass the queue
// depth limit after eviction resets their entry to level 0.
func TestLeakyBucket_EvictTTLAccountsForDrainDuration(t *testing.T) {
	// Arrange — drain rate 0.0001 req/s with depth 1 gives:
	// drainDuration = 1/0.0001 s = 10000 s >> rlshard.StaleEntryTTL (10 min = 600 s).
	// evictTTL = max(600s, 10000s) = 10000s.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rl := New(ctx, domain.LeakyBucketRule{
		DrainRatePerSecond: 0.0001,
		QueueDepth:         1,
	})

	// Act — fill the queue to capacity, then simulate eviction at rlshard.StaleEntryTTL+1ns
	// past lastSeen. This is past the OLD rlshard.StaleEntryTTL threshold but well within
	// the NEW evictTTL (10000s).
	if !rl.Allow("client") {
		t.Fatal("first request should be allowed")
	}
	future := time.Now().Add(rlshard.StaleEntryTTL + time.Nanosecond)
	rl.evictShard(int(shardIndex("client")), future)

	// Assert — entry must NOT have been evicted.
	// If evicted: Allow creates a fresh entry at level=1 → returns true (bug).
	// If retained: level=1 >= depth=1 → returns false (correct).
	if rl.Allow("client") {
		t.Error("queue-full entry evicted prematurely: evictTTL must account for drain duration")
	}
}
