//go:build unit

package roundrobin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/roundrobin"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// captureTransport records the route.Upstream.URL that was passed on each Forward call.
type captureTransport struct {
	urls []string
}

var _ ports.UpstreamTransport = (*captureTransport)(nil)

func (c *captureTransport) Forward(w http.ResponseWriter, _ *http.Request, route *domain.Route) error {
	c.urls = append(c.urls, route.Upstream.URL)
	w.WriteHeader(http.StatusOK)
	return nil
}

func routeWithURLs(name string, urls []string) *domain.Route {
	return &domain.Route{
		Name: name,
		Upstream: domain.UpstreamTarget{
			URLs: urls,
			URL:  urls[0],
		},
	}
}

// --- Compile-time interface check ---

func TestTransport_ImplementsUpstreamTransport(t *testing.T) {
	var _ ports.UpstreamTransport = roundrobin.NewTransport(
		&captureTransport{},
		roundrobin.NewPicker(),
	)
}

// --- Single URL: pass-through behaviour ---

// TestTransport_SingleURL_DelegatesToInner checks that a route with a single URL
// is forwarded unchanged — the round-robin decorator adds no observable effect.
func TestTransport_SingleURL_DelegatesToInner(t *testing.T) {
	inner := &captureTransport{}
	tr := roundrobin.NewTransport(inner, roundrobin.NewPicker())

	r := routeWithURLs("svc", []string{"http://only:8080"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	if err := tr.Forward(rr, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inner.urls) != 1 || inner.urls[0] != "http://only:8080" {
		t.Errorf("inner saw URL %v, want [http://only:8080]", inner.urls)
	}
}

// --- Round-robin distribution ---

// TestTransport_RoundRobin_DistributesAcrossPool verifies that successive requests
// to a multi-URL route cycle through all endpoints in order.
func TestTransport_RoundRobin_DistributesAcrossPool(t *testing.T) {
	urls := []string{"http://a:8080", "http://b:8080", "http://c:8080"}
	inner := &captureTransport{}
	tr := roundrobin.NewTransport(inner, roundrobin.NewPicker())

	r := routeWithURLs("svc", urls)
	for range len(urls) * 2 { // two full cycles
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		if err := tr.Forward(httptest.NewRecorder(), req, r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	want := []string{
		"http://a:8080", "http://b:8080", "http://c:8080",
		"http://a:8080", "http://b:8080", "http://c:8080",
	}
	if len(inner.urls) != len(want) {
		t.Fatalf("got %d forward calls, want %d", len(inner.urls), len(want))
	}
	for i, w := range want {
		if inner.urls[i] != w {
			t.Errorf("call %d: inner received URL %q, want %q", i+1, inner.urls[i], w)
		}
	}
}

// --- Route struct is not mutated ---

// TestTransport_DoesNotMutateRoute confirms that the original route value is
// unchanged after Forward completes. The decorator must work on a copy.
func TestTransport_DoesNotMutateRoute(t *testing.T) {
	urls := []string{"http://a:8080", "http://b:8080"}
	r := routeWithURLs("svc", urls)
	originalURL := r.Upstream.URL

	inner := &captureTransport{}
	tr := roundrobin.NewTransport(inner, roundrobin.NewPicker())

	for range 4 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := tr.Forward(httptest.NewRecorder(), req, r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if r.Upstream.URL != originalURL {
		t.Errorf("route.Upstream.URL was mutated: got %q, want %q", r.Upstream.URL, originalURL)
	}
}
