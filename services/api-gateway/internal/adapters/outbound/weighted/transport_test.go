//go:build unit

package weighted_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/proxy"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/weighted"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func TestWeightedTransport_ImplementsUpstreamTransport(t *testing.T) {
	var _ ports.UpstreamTransport = weighted.NewTransport(
		proxy.NewTransport(&http.Client{}),
		weighted.NewPicker(),
	)
}

func TestWeightedTransport_ForwardsRequestToSelectedURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	inner := proxy.NewTransport(&http.Client{})
	tr := weighted.NewTransport(inner, weighted.NewPicker())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)

	route := &domain.Route{
		Name: "test-svc",
		Upstream: domain.UpstreamTarget{
			URL:     upstream.URL,
			URLs:    []string{upstream.URL},
			Weights: []int{1},
		},
	}

	if err := tr.Forward(rr, req, route); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestWeightedTransport_DoesNotMutateOriginalRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	inner := proxy.NewTransport(&http.Client{})
	tr := weighted.NewTransport(inner, weighted.NewPicker())

	originalURL := "http://original-placeholder:9999"
	route := &domain.Route{
		Name: "no-mutation",
		Upstream: domain.UpstreamTarget{
			URL:  originalURL,
			URLs: []string{upstream.URL},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = tr.Forward(rr, req, route)

	if route.Upstream.URL != originalURL {
		t.Errorf("original route was mutated: URL changed from %q to %q", originalURL, route.Upstream.URL)
	}
}
