//go:build unit

package slidingwindowlog

import (
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/rlshard"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

func TestEvictStale_RemovesExpiredKey(t *testing.T) {
	// Arrange
	window := 10 * time.Millisecond
	rl := &RateLimiter{rule: domain.SlidingWindowLogRule{
		RequestsPerWindow: 100,
		WindowDuration:    window,
	}}
	for i := range rlshard.NumShards {
		rl.shards[i].logs = make(map[string][]time.Time)
	}
	rl.Allow("evict-me")
	// Backdate the log entry so evictStale treats the key as stale.
	idx := shardIndex("evict-me")
	rl.shards[idx].mu.Lock()
	rl.shards[idx].logs["evict-me"] = []time.Time{
		time.Now().Add(-(window + time.Second)),
	}
	rl.shards[idx].mu.Unlock()

	// Act
	rl.evictStale()

	// Assert
	rl.shards[idx].mu.Lock()
	_, present := rl.shards[idx].logs["evict-me"]
	rl.shards[idx].mu.Unlock()
	if present {
		t.Fatal("expected stale key to be removed from the map by evictStale")
	}
}

func TestEvictStale_PreservesActiveKey(t *testing.T) {
	// Arrange
	rl := &RateLimiter{rule: domain.SlidingWindowLogRule{
		RequestsPerWindow: 100,
		WindowDuration:    time.Hour,
	}}
	for i := range rlshard.NumShards {
		rl.shards[i].logs = make(map[string][]time.Time)
	}
	rl.Allow("keep-me")

	// Act
	rl.evictStale()

	// Assert
	idx := shardIndex("keep-me")
	rl.shards[idx].mu.Lock()
	_, present := rl.shards[idx].logs["keep-me"]
	rl.shards[idx].mu.Unlock()
	if !present {
		t.Fatal("entry within active window must not be evicted")
	}
}
