//go:build unit

package weighted_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/weighted"
)

func TestPicker_Pick_EmptyURLsReturnsEmpty(t *testing.T) {
	p := weighted.NewPicker()
	if got := p.Pick("route", nil, nil); got != "" {
		t.Errorf("expected empty string for empty URL pool, got %q", got)
	}
}

func TestPicker_Pick_SingleURLAlwaysReturnsIt(t *testing.T) {
	p := weighted.NewPicker()
	for i := 0; i < 10; i++ {
		got := p.Pick("route", []string{"http://svc:8080"}, []int{5})
		if got != "http://svc:8080" {
			t.Errorf("expected single URL, got %q", got)
		}
	}
}

func TestPicker_Pick_NoWeightsDegradesToUniform(t *testing.T) {
	p := weighted.NewPicker()
	urls := []string{"http://a:8080", "http://b:8080", "http://c:8080"}

	seen := make(map[string]int)
	for i := 0; i < 300; i++ {
		seen[p.Pick("route", urls, nil)]++
	}
	// Every URL must be selected at least once in 300 attempts (probability of
	// missing any single URL is negligibly small with uniform distribution).
	for _, u := range urls {
		if seen[u] == 0 {
			t.Errorf("URL %q was never selected in 300 uniform picks", u)
		}
	}
}

func TestPicker_Pick_EqualWeightsDegradesToUniform(t *testing.T) {
	p := weighted.NewPicker()
	urls := []string{"http://a:8080", "http://b:8080"}
	weights := []int{3, 3}

	seen := make(map[string]int)
	for i := 0; i < 200; i++ {
		seen[p.Pick("equal", urls, weights)]++
	}
	for _, u := range urls {
		if seen[u] == 0 {
			t.Errorf("URL %q was never selected with equal weights", u)
		}
	}
}

func TestPicker_Pick_WeightedDistribution(t *testing.T) {
	p := weighted.NewPicker()
	// primary gets 3× the weight of canary — roughly 75% vs 25%.
	urls := []string{"http://primary:8080", "http://canary:8080"}
	weights := []int{3, 1}

	seen := make(map[string]int)
	const n = 10000
	for i := 0; i < n; i++ {
		seen[p.Pick("svc", urls, weights)]++
	}

	primaryRatio := float64(seen["http://primary:8080"]) / float64(n)
	// With weight 3:1 the primary should be selected ~75% of the time.
	// Allow ±10% tolerance for randomness in a 10 000-sample run.
	if primaryRatio < 0.65 || primaryRatio > 0.85 {
		t.Errorf("primary selection ratio = %.2f, expected ~0.75 (weight 3:1)", primaryRatio)
	}
}

func TestPicker_Pick_ZeroWeightURLsNeverSelected(t *testing.T) {
	p := weighted.NewPicker()
	urls := []string{"http://active:8080", "http://disabled:8080"}
	weights := []int{1, 0}

	for i := 0; i < 200; i++ {
		got := p.Pick("route", urls, weights)
		if got == "http://disabled:8080" {
			t.Fatal("URL with zero weight was selected")
		}
	}
}

func TestPicker_Pick_IsSafeForConcurrentUse(t *testing.T) {
	p := weighted.NewPicker()
	urls := []string{"http://a:8080", "http://b:8080"}
	weights := []int{2, 1}

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			p.Pick("concurrent-route", urls, weights)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
