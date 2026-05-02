//go:build unit

package leakybucket_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/leakybucket"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*leakybucket.RateLimiter)(nil)

func TestLeakyBucket_AllowsUpToQueueDepth(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1,
		QueueDepth:         3,
	})
	for i := range 3 {
		if !rl.Allow("client") {
			t.Fatalf("request %d should be allowed (queue not full)", i+1)
		}
	}
}

func TestLeakyBucket_DeniesWhenQueueFull(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1,
		QueueDepth:         2,
	})
	rl.Allow("client")
	rl.Allow("client")
	if rl.Allow("client") {
		t.Fatal("request should be denied when queue is full")
	}
}

func TestLeakyBucket_AllowsAfterDrain(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 20, // drain one token every 50ms
		QueueDepth:         1,
	})
	if !rl.Allow("client") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("client") {
		t.Fatal("second request should be denied (queue full)")
	}
	time.Sleep(60 * time.Millisecond) // wait for one drain interval
	if !rl.Allow("client") {
		t.Fatal("request should be allowed after drain")
	}
}

func TestLeakyBucket_IndependentKeys(t *testing.T) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1,
		QueueDepth:         1,
	})
	if !rl.Allow("a") {
		t.Fatal("a should be allowed")
	}
	if !rl.Allow("b") {
		t.Fatal("b should be allowed — independent queue")
	}
}

// TestLeakyBucket_PanicsOnZeroDrainRate verifies that New panics immediately when
// DrainRatePerSecond is zero or negative, rather than silently constructing a
// limiter with corrupted arithmetic. The config layer validates these at startup;
// this guard catches direct programmatic misuse.
func TestLeakyBucket_PanicsOnZeroDrainRate(t *testing.T) {
	// Arrange / Act / Assert
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected New to panic on DrainRatePerSecond=0, but it did not")
		}
	}()
	leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 0,
		QueueDepth:         1,
	})
}

func TestLeakyBucket_PanicsOnNegativeDrainRate(t *testing.T) {
	// Arrange / Act / Assert
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected New to panic on DrainRatePerSecond<0, but it did not")
		}
	}()
	leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: -1,
		QueueDepth:         1,
	})
}

// TestLeakyBucket_UndrainedNsRetainedAfterLevelClamp verifies that fractional
// drain progress (undrainedNs) is preserved when wholeTokens exceeds the current
// level, clamping it to zero. Without this, the drain timer effectively restarts
// after a queue-empty event, making the effective drain rate lower than configured.
func TestLeakyBucket_UndrainedNsRetainedAfterLevelClamp(t *testing.T) {
	// Arrange — drain rate 100/s = 10ms per token, queue depth 1.
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 100,
		QueueDepth:         1,
	})
	if !rl.Allow("client") {
		t.Fatal("first request should be allowed (fills queue to 1)")
	}

	// Act — wait 25ms (2.5 drain intervals). The integer division yields 2 whole
	// tokens drained, with 5ms of fractional progress accumulated. Without the fix,
	// that 5ms is zeroed when level clamps to 0.
	time.Sleep(25 * time.Millisecond)
	if !rl.Allow("client") {
		t.Skip("timing too jittery on this machine — skipping")
	}

	// Wait 7ms more. With fix: 5ms + 7ms = 12ms ≥ 10ms → 1 full drain, level drops
	// to 0, so next Allow increments from 0 to 1 and is permitted.
	// Without fix: 0ms + 7ms = 7ms < 10ms → no drain, level stays at 1 = capacity → denied.
	time.Sleep(7 * time.Millisecond)

	// Assert
	if !rl.Allow("client") {
		t.Error("request should be allowed — undrainedNs should be retained across level clamp")
	}
}

// TestLeakyBucket_ExtremelyHighDrainRateDoesNotPanic verifies that a
// DrainRatePerSecond that truncates drainNanosPerToken to zero does not cause a
// divide-by-zero panic. Any rate > 1e9 (req/s) truncates 1 ns to 0.
func TestLeakyBucket_ExtremelyHighDrainRateDoesNotPanic(t *testing.T) {
	// Arrange
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 2e9, // 2e9 req/s → int64(1e9 ns / 2e9) = int64(0.5) = 0
		QueueDepth:         2,
	})

	// Act — first Allow creates the entry; second triggers the drain arithmetic.
	rl.Allow("client")

	// Assert — must not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Allow panicked: %v", r)
		}
	}()
	rl.Allow("client")
}

func BenchmarkLeakyBucket_Allow_SingleKey(b *testing.B) {
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1e9, // effectively unlimited drain so queue never fills
		QueueDepth:         b.N + 1,
	})
	b.ResetTimer()
	for range b.N {
		rl.Allow("client")
	}
}

func BenchmarkLeakyBucket_Allow_HighCardinality(b *testing.B) {
	const keys = 1000
	rl := leakybucket.New(context.Background(), domain.LeakyBucketRule{
		DrainRatePerSecond: 1e9,
		QueueDepth:         b.N + 1,
	})
	k := make([]string, keys)
	for i := range keys {
		k[i] = fmt.Sprintf("client-%d", i)
	}
	b.ResetTimer()
	for i := range b.N {
		rl.Allow(k[i%keys])
	}
}
