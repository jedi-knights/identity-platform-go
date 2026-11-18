package jwks_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/jwks"
)

// controllableJWKS fronts a healthy JWKS server with switchable latency and
// failure so tests can model a slow or unreachable upstream.
type controllableJWKS struct {
	*httptest.Server
	hits  atomic.Int64
	delay atomic.Int64 // nanoseconds
	fail  atomic.Bool
}

func newControllableJWKS(t *testing.T, keys ...keyEntry) *controllableJWKS {
	t.Helper()
	inner := fakeJWKSServer(t, nil, keys...)
	c := &controllableJWKS{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		time.Sleep(time.Duration(c.delay.Load()))
		if c.fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp, err := http.Get(inner.URL) //nolint:gosec,noctx // G107/noctx: test-only fixture URL from httptest.
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(c.Close)
	return c
}

// lookupAll runs n concurrent KeyByID calls and returns the errors in order.
func lookupAll(f *jwks.Fetcher, kid string, n int) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.KeyByID(context.Background(), kid)
		}()
	}
	wg.Wait()
	return errs
}

func TestFetcher_StaleBurst_SharesOneRefresh(t *testing.T) {
	// Arrange: warm the cache, let it go stale, make the upstream slow.
	priv := newRSAKey(t)
	up := newControllableJWKS(t, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewFetcher(up.URL, jwks.WithCacheTTL(20*time.Millisecond))
	if _, err := f.KeyByID(context.Background(), "kid-a"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	up.delay.Store(int64(100 * time.Millisecond))

	// Act
	errs := lookupAll(f, "kid-a", 16)

	// Assert: every caller succeeds from ONE shared refresh (plus warm-up).
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := up.hits.Load(); got > 2 {
		t.Fatalf("upstream hit %d times; want <= 2 (warm-up + one shared refresh)", got)
	}
}

func TestFetcher_StaleBurst_UpstreamDown_SharesOneFailure(t *testing.T) {
	priv := newRSAKey(t)
	up := newControllableJWKS(t, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewFetcher(up.URL, jwks.WithCacheTTL(20*time.Millisecond))
	if _, err := f.KeyByID(context.Background(), "kid-a"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	up.fail.Store(true)
	up.delay.Store(int64(50 * time.Millisecond))

	errs := lookupAll(f, "kid-a", 16)

	// Fail-closed is preserved: nobody gets a key from a stale cache.
	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d: got a key from a stale cache with the upstream down", i)
		}
	}
	if got := up.hits.Load(); got > 2 {
		t.Fatalf("upstream hit %d times; want <= 2 (warm-up + one shared failed refresh)", got)
	}
}

func TestFetcher_FreshKnownKey_NotBlockedByInFlightRefresh(t *testing.T) {
	priv := newRSAKey(t)
	up := newControllableJWKS(t, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewFetcher(up.URL, jwks.WithCacheTTL(time.Hour), jwks.WithRefreshRateLimit(0))
	if _, err := f.KeyByID(context.Background(), "kid-a"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	up.delay.Store(int64(400 * time.Millisecond))
	go func() { _, _ = f.KeyByID(context.Background(), "unknown-kid") }() // slow forced refresh
	time.Sleep(50 * time.Millisecond)                                     // let it enter the upstream call

	start := time.Now()
	_, err := f.KeyByID(context.Background(), "kid-a")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("cached key lookup took %v behind an in-flight refresh; want < 100ms", elapsed)
	}
}
