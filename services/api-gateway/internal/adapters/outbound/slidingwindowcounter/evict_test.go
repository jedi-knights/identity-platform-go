//go:build unit

package slidingwindowcounter

import (
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/rlshard"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

func TestEvictStale_RemovesStaleEntry(t *testing.T) {
	// Arrange
	rl := &RateLimiter{rule: domain.SlidingWindowCounterRule{
		RequestsPerWindow: 100,
		WindowDuration:    time.Millisecond,
	}}
	for i := range rlshard.NumShards {
		rl.shards[i].entries = make(map[string]*entry)
	}
	rl.Allow("stale")
	idx := shardIndex("stale")
	rl.shards[idx].mu.Lock()
	rl.shards[idx].entries["stale"].lastSeen = time.Now().Add(-(rlshard.StaleEntryTTL + time.Second))
	rl.shards[idx].mu.Unlock()

	// Act
	rl.evictStale()

	// Assert
	rl.shards[idx].mu.Lock()
	_, present := rl.shards[idx].entries["stale"]
	rl.shards[idx].mu.Unlock()
	if present {
		t.Fatal("expected stale entry to be removed by evictStale")
	}
}

func TestEvictStale_PreservesActiveLongWindowEntry(t *testing.T) {
	// Arrange — window duration (20 min) > rlshard.StaleEntryTTL (10 min);
	// the max() guard must prevent eviction of a recently-seen entry.
	longWindow := 20 * time.Minute
	rl := &RateLimiter{rule: domain.SlidingWindowCounterRule{
		RequestsPerWindow: 100,
		WindowDuration:    longWindow,
	}}
	for i := range rlshard.NumShards {
		rl.shards[i].entries = make(map[string]*entry)
	}
	rl.Allow("active")

	// Act
	rl.evictStale()

	// Assert
	idx := shardIndex("active")
	rl.shards[idx].mu.Lock()
	_, present := rl.shards[idx].entries["active"]
	rl.shards[idx].mu.Unlock()
	if !present {
		t.Fatal("entry seen recently within an active long window must not be evicted")
	}
}
