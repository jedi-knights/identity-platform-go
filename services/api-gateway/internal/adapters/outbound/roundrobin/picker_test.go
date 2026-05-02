//go:build unit

package roundrobin_test

import (
	"sync"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/roundrobin"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// --- Compile-time interface check ---

func TestPicker_ImplementsURLPicker(t *testing.T) {
	var _ ports.URLPicker = roundrobin.NewPicker()
}

// --- Single URL pool ---

// TestPicker_SingleURL_AlwaysReturnsThatURL verifies that a 1-element pool
// always returns the sole URL regardless of how many times Pick is called.
func TestPicker_SingleURL_AlwaysReturnsThatURL(t *testing.T) {
	p := roundrobin.NewPicker()
	for range 5 {
		got := p.Pick("svc", []string{"http://svc:8080"})
		if got != "http://svc:8080" {
			t.Errorf("Pick = %q, want %q", got, "http://svc:8080")
		}
	}
}

// --- Round-robin ordering ---

// TestPicker_RoundRobin_CyclesInOrder confirms that successive calls distribute
// across the pool in order and wrap around.
func TestPicker_RoundRobin_CyclesInOrder(t *testing.T) {
	urls := []string{"http://a:8080", "http://b:8080", "http://c:8080"}
	p := roundrobin.NewPicker()

	want := []string{
		"http://a:8080",
		"http://b:8080",
		"http://c:8080",
		"http://a:8080", // wraps
		"http://b:8080",
	}

	for i, w := range want {
		got := p.Pick("svc", urls)
		if got != w {
			t.Errorf("call %d: Pick = %q, want %q", i+1, got, w)
		}
	}
}

// --- Per-route isolation ---

// TestPicker_PerRoute_IndependentCounters verifies that counters for different
// route names are independent — cycling one route does not affect another.
func TestPicker_PerRoute_IndependentCounters(t *testing.T) {
	urls := []string{"http://1:8080", "http://2:8080"}
	p := roundrobin.NewPicker()

	// Advance route-a counter twice.
	p.Pick("route-a", urls) // → 1
	p.Pick("route-a", urls) // → 2 (wraps to index 1)

	// route-b should start fresh at index 0.
	if got := p.Pick("route-b", urls); got != "http://1:8080" {
		t.Errorf("route-b first pick = %q, want %q", got, "http://1:8080")
	}
}

// --- Empty pool edge case ---

// TestPicker_EmptyURLs_ReturnsEmpty checks the degenerate case that can only
// occur if validation is bypassed.
func TestPicker_EmptyURLs_ReturnsEmpty(t *testing.T) {
	p := roundrobin.NewPicker()
	if got := p.Pick("svc", nil); got != "" {
		t.Errorf("Pick with nil urls = %q, want empty string", got)
	}
}

// --- Concurrency ---

// TestPicker_ConcurrentPicks verifies that the picker produces no data races
// and covers all URLs when called concurrently from many goroutines.
func TestPicker_ConcurrentPicks_NoPanic(t *testing.T) {
	urls := []string{"http://a:8080", "http://b:8080", "http://c:8080"}
	p := roundrobin.NewPicker()

	const goroutines = 50
	const picks = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range picks {
				got := p.Pick("svc", urls)
				found := false
				for _, u := range urls {
					if u == got {
						found = true
						break
					}
				}
				if !found {
					// t.Error cannot be called from a goroutine safely in all Go
					// versions; use panic so the test fails with a clear message.
					panic("Pick returned URL not in pool: " + got)
				}
			}
		}()
	}
	wg.Wait()
}
