//go:build unit

package static_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/static"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func route(name, prefix string, methods ...string) *domain.Route {
	return &domain.Route{
		Name:     name,
		Match:    domain.MatchCriteria{PathPrefix: prefix, Methods: methods},
		Upstream: domain.UpstreamTarget{URL: "http://" + name + ":8080"},
	}
}

func TestResolver_Resolve_ReturnsMatchingRoute(t *testing.T) {
	r := static.NewResolver([]*domain.Route{
		route("svc-a", "/api/a"),
		route("svc-b", "/api/b"),
	})

	got, err := r.Resolve(context.Background(), "GET", "/api/a/resource", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "svc-a" {
		t.Errorf("got route %q, want %q", got.Name, "svc-a")
	}
}

func TestResolver_Resolve_ReturnsNoRouteMatchedWhenNoneMatch(t *testing.T) {
	r := static.NewResolver([]*domain.Route{
		route("svc-a", "/api/a"),
	})

	_, err := r.Resolve(context.Background(), "GET", "/unknown", nil)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ports.ErrNoRouteMatched) {
		t.Errorf("expected ErrNoRouteMatched in error chain, got: %v", err)
	}
}

func TestResolver_Resolve_EmptyRouteListReturnsNoMatch(t *testing.T) {
	r := static.NewResolver(nil)

	_, err := r.Resolve(context.Background(), "GET", "/api", nil)

	if !errors.Is(err, ports.ErrNoRouteMatched) {
		t.Errorf("expected ErrNoRouteMatched, got: %v", err)
	}
}

func TestResolver_Resolve_LongerPrefixWinsOverShorterPrefix(t *testing.T) {
	// "/api/users" is more specific than "/api" — it should win even though
	// "/api" was added first.
	r := static.NewResolver([]*domain.Route{
		route("broad", "/api"),
		route("specific", "/api/users"),
	})

	got, err := r.Resolve(context.Background(), "GET", "/api/users/123", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "specific" {
		t.Errorf("got route %q, want %q (more specific prefix should win)", got.Name, "specific")
	}
}

func TestResolver_Resolve_BroadRouteMatchesWhenSpecificDoesNot(t *testing.T) {
	r := static.NewResolver([]*domain.Route{
		route("broad", "/api"),
		route("specific", "/api/users"),
	})

	got, err := r.Resolve(context.Background(), "GET", "/api/orders/5", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "broad" {
		t.Errorf("got route %q, want %q", got.Name, "broad")
	}
}

func TestResolver_Resolve_MethodFilterApplied(t *testing.T) {
	r := static.NewResolver([]*domain.Route{
		route("post-only", "/api", "POST"),
	})

	_, err := r.Resolve(context.Background(), "GET", "/api/resource", nil)

	if !errors.Is(err, ports.ErrNoRouteMatched) {
		t.Errorf("GET should not match a POST-only route, got: %v", err)
	}
}

func TestResolver_Resolve_HeaderFilterApplied(t *testing.T) {
	r := static.NewResolver([]*domain.Route{
		{
			Name: "versioned",
			Match: domain.MatchCriteria{
				PathPrefix: "/api",
				Headers:    map[string]string{"X-API-Version": "v2"},
			},
			Upstream: domain.UpstreamTarget{URL: "http://versioned:8080"},
		},
	})

	t.Run("matching header", func(t *testing.T) {
		got, err := r.Resolve(context.Background(), "GET", "/api/resource", map[string]string{"X-API-Version": "v2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name != "versioned" {
			t.Errorf("got route %q, want %q", got.Name, "versioned")
		}
	})

	t.Run("non-matching header", func(t *testing.T) {
		_, err := r.Resolve(context.Background(), "GET", "/api/resource", map[string]string{"X-API-Version": "v1"})
		if !errors.Is(err, ports.ErrNoRouteMatched) {
			t.Errorf("expected ErrNoRouteMatched for header mismatch, got: %v", err)
		}
	})
}

func TestResolver_Resolve_InputSliceIsNotMutated(t *testing.T) {
	original := []*domain.Route{
		route("broad", "/api"),
		route("specific", "/api/users"),
	}
	// Record original order before resolver construction.
	originalFirst := original[0].Name

	static.NewResolver(original)

	// Resolver sorts internally — original slice must be unchanged.
	if original[0].Name != originalFirst {
		t.Error("NewResolver must not mutate the caller's route slice")
	}
}
