//go:build unit

package slidingwindowcounter_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/slidingwindowcounter"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*slidingwindowcounter.RateLimiter)(nil)

// TestSlidingWindowCounter_PanicsOnZeroWindowDuration verifies that New panics
// when WindowDuration is zero, which would otherwise cause float64 division-by-zero
// in Allow, producing +Inf/-Inf and allowing unlimited requests regardless of limit.
func TestSlidingWindowCounter_PanicsOnZeroWindowDuration(t *testing.T) {
	// Arrange / Act / Assert
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected New to panic on WindowDuration=0, but it did not")
		}
	}()
	slidingwindowcounter.New(context.Background(), domain.SlidingWindowCounterRule{
		WindowRule: domain.WindowRule{
			RequestsPerWindow: 10,
			WindowDuration:    0,
		},
	})
}

func TestSlidingWindowCounter_AllowsUpToLimit(t *testing.T) {
	rl := slidingwindowcounter.New(context.Background(), domain.SlidingWindowCounterRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 3,
		WindowDuration:    time.Second,
	}})
	for i := range 3 {
		if !rl.Allow("client") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestSlidingWindowCounter_DeniesOverLimit(t *testing.T) {
	rl := slidingwindowcounter.New(context.Background(), domain.SlidingWindowCounterRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 2,
		WindowDuration:    time.Second,
	}})
	rl.Allow("client")
	rl.Allow("client")
	if rl.Allow("client") {
		t.Fatal("third request should be denied")
	}
}

func TestSlidingWindowCounter_ResetsAfterFullWindow(t *testing.T) {
	rl := slidingwindowcounter.New(context.Background(), domain.SlidingWindowCounterRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 2,
		WindowDuration:    60 * time.Millisecond,
	}})
	rl.Allow("client")
	rl.Allow("client")
	// Wait for both the current and previous windows to expire.
	time.Sleep(130 * time.Millisecond)
	if !rl.Allow("client") {
		t.Fatal("request should be allowed after both windows have expired")
	}
}

func TestSlidingWindowCounter_IndependentKeys(t *testing.T) {
	rl := slidingwindowcounter.New(context.Background(), domain.SlidingWindowCounterRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 1,
		WindowDuration:    time.Second,
	}})
	if !rl.Allow("a") {
		t.Fatal("a should be allowed")
	}
	if !rl.Allow("b") {
		t.Fatal("b should be allowed — independent counters")
	}
}

func BenchmarkSlidingWindowCounter_Allow_SingleKey(b *testing.B) {
	rl := slidingwindowcounter.New(context.Background(), domain.SlidingWindowCounterRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: b.N + 1,
		WindowDuration:    time.Hour,
	}})
	b.ResetTimer()
	for range b.N {
		rl.Allow("client")
	}
}

func BenchmarkSlidingWindowCounter_Allow_HighCardinality(b *testing.B) {
	const keys = 1000
	rl := slidingwindowcounter.New(context.Background(), domain.SlidingWindowCounterRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: b.N + 1,
		WindowDuration:    time.Hour,
	}})
	k := make([]string, keys)
	for i := range keys {
		k[i] = fmt.Sprintf("client-%d", i)
	}
	b.ResetTimer()
	for i := range b.N {
		rl.Allow(k[i%keys])
	}
}
