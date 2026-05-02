//go:build unit

package slidingwindowlog_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/slidingwindowlog"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.RateLimiter = (*slidingwindowlog.RateLimiter)(nil)

func TestSlidingWindowLog_AllowsUpToLimit(t *testing.T) {
	rl := slidingwindowlog.New(context.Background(), domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 3,
		WindowDuration:    time.Second,
	}})
	for i := range 3 {
		if !rl.Allow("client") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestSlidingWindowLog_DeniesOverLimit(t *testing.T) {
	rl := slidingwindowlog.New(context.Background(), domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 2,
		WindowDuration:    time.Second,
	}})
	rl.Allow("client")
	rl.Allow("client")
	if rl.Allow("client") {
		t.Fatal("third request should be denied")
	}
}

func TestSlidingWindowLog_AllowsAfterWindowSlides(t *testing.T) {
	rl := slidingwindowlog.New(context.Background(), domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 1,
		WindowDuration:    60 * time.Millisecond,
	}})
	if !rl.Allow("client") {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("client") {
		t.Fatal("second request should be denied while first is still in window")
	}
	time.Sleep(70 * time.Millisecond)
	// The first request has now slid out of the window.
	if !rl.Allow("client") {
		t.Fatal("request should be allowed once the window has slid past the first entry")
	}
}

func TestSlidingWindowLog_IndependentKeys(t *testing.T) {
	rl := slidingwindowlog.New(context.Background(), domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 1,
		WindowDuration:    time.Second,
	}})
	if !rl.Allow("a") {
		t.Fatal("a should be allowed")
	}
	if !rl.Allow("b") {
		t.Fatal("b should be allowed — independent log")
	}
}

func TestSlidingWindowLog_AllowRecountsAfterWindowExpiry(t *testing.T) {
	rl := slidingwindowlog.New(context.Background(), domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: 100,
		WindowDuration:    10 * time.Millisecond,
	}})
	rl.Allow("client")
	time.Sleep(20 * time.Millisecond)
	// The window has expired; Allow's inline eviction must reset the in-window count.
	if !rl.Allow("client") {
		t.Fatal("Allow should be permitted after the window expires (inline eviction resets count)")
	}
}

func BenchmarkSlidingWindowLog_Allow_SingleKey(b *testing.B) {
	rl := slidingwindowlog.New(context.Background(), domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
		RequestsPerWindow: b.N + 1,
		WindowDuration:    time.Hour,
	}})
	b.ResetTimer()
	for range b.N {
		rl.Allow("client")
	}
}

func BenchmarkSlidingWindowLog_Allow_HighCardinality(b *testing.B) {
	const keys = 1000
	rl := slidingwindowlog.New(context.Background(), domain.SlidingWindowLogRule{WindowRule: domain.WindowRule{
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
