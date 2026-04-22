//go:build unit

package config_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
)

func TestConfig_ToDomainRoutes_MapsAllFields(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{
				Name: "identity",
				Match: config.MatchConfig{
					PathPrefix: "/api/identity",
					Methods:    []string{"GET", "POST"},
					Headers:    map[string]string{"X-Version": "v2"},
				},
				Upstream: config.UpstreamConfig{
					URL:         "http://identity-service:8080",
					StripPrefix: "/api/identity",
				},
			},
		},
	}

	routes := cfg.ToDomainRoutes()

	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	r := routes[0]
	if r.Name != "identity" {
		t.Errorf("Name = %q, want %q", r.Name, "identity")
	}
	if r.Match.PathPrefix != "/api/identity" {
		t.Errorf("PathPrefix = %q, want %q", r.Match.PathPrefix, "/api/identity")
	}
	if len(r.Match.Methods) != 2 {
		t.Errorf("Methods count = %d, want 2", len(r.Match.Methods))
	}
	if r.Match.Headers["X-Version"] != "v2" {
		t.Errorf("Headers[X-Version] = %q, want %q", r.Match.Headers["X-Version"], "v2")
	}
	if r.Upstream.URL != "http://identity-service:8080" {
		t.Errorf("Upstream.URL = %q, want %q", r.Upstream.URL, "http://identity-service:8080")
	}
	if r.Upstream.StripPrefix != "/api/identity" {
		t.Errorf("Upstream.StripPrefix = %q, want %q", r.Upstream.StripPrefix, "/api/identity")
	}
}

func TestConfig_ToDomainRoutes_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	routes := cfg.ToDomainRoutes()
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestConfig_ToDomainRoutes_MultipleRoutes(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{Name: "svc-a", Upstream: config.UpstreamConfig{URL: "http://a:8080"}},
			{Name: "svc-b", Upstream: config.UpstreamConfig{URL: "http://b:8080"}},
			{Name: "svc-c", Upstream: config.UpstreamConfig{URL: "http://c:8080"}},
		},
	}

	routes := cfg.ToDomainRoutes()

	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	for i, want := range []string{"svc-a", "svc-b", "svc-c"} {
		if routes[i].Name != want {
			t.Errorf("routes[%d].Name = %q, want %q", i, routes[i].Name, want)
		}
	}
}

func TestConfig_ToDomainRoutes_NilHeadersArePropagated(t *testing.T) {
	cfg := &config.Config{
		Routes: []config.RouteConfig{
			{
				Name:     "no-headers",
				Match:    config.MatchConfig{PathPrefix: "/api"},
				Upstream: config.UpstreamConfig{URL: "http://svc:8080"},
			},
		},
	}

	routes := cfg.ToDomainRoutes()

	if routes[0].Match.Headers != nil {
		t.Errorf("expected nil headers, got %v", routes[0].Match.Headers)
	}
}
