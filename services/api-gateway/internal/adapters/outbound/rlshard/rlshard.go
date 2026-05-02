// Package rlshard provides the shared sharding constants used by all in-memory
// rate-limiter adapters (fixedwindow, slidingwindowcounter, slidingwindowlog,
// leakybucket). Centralising these values ensures that all limiters behave
// consistently and that changes to the shard count or eviction cadence only
// need to be made in one place.
package rlshard

import "time"

const (
	// NumShards is the number of independent mutex-protected buckets used by all
	// rate-limiter adapters. 16 shards reduce contention by a factor of ~16 under
	// high-cardinality traffic without requiring a concurrent map.
	NumShards = 16

	// StaleEntryTTL is the minimum time after which an entry that has received no
	// traffic is eligible for eviction. Adapters may choose a longer effective TTL
	// (e.g. max(StaleEntryTTL, windowDuration)) to avoid prematurely evicting entries
	// whose state has not yet fully expired.
	StaleEntryTTL = 10 * time.Minute

	// EvictTick is how often the background eviction goroutine wakes up to remove
	// stale entries. A 1-minute tick bounds the worst-case memory overshoot to
	// approximately one minute of idle-key accumulation.
	EvictTick = time.Minute
)
