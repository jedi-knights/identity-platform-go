package static

import (
	"context"
	"sort"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Resolver implements ports.RouteResolver using a static list of routes loaded
// at construction time from configuration. Routes are sorted by descending path
// prefix length so that more specific routes take precedence over broader ones.
//
// Example: "/api/users" wins over "/api" for a request to "/api/users/123".
type Resolver struct {
	routes []*domain.Route
}

// Compile-time check: Resolver must satisfy ports.RouteResolver.
var _ ports.RouteResolver = (*Resolver)(nil)

// NewResolver creates a Resolver from routes. The slice is copied and sorted
// internally; the caller's slice is not modified.
func NewResolver(routes []*domain.Route) *Resolver {
	sorted := make([]*domain.Route, len(routes))
	copy(sorted, routes)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].Match.PathPrefix) > len(sorted[j].Match.PathPrefix)
	})
	return &Resolver{routes: sorted}
}

// Resolve iterates routes in specificity order and returns the first match.
// It returns a NOT_FOUND AppError wrapping ports.ErrNoRouteMatched when no
// configured route satisfies the request attributes.
func (r *Resolver) Resolve(_ context.Context, method, path string, headers map[string]string) (*domain.Route, error) {
	for _, route := range r.routes {
		if route.Matches(method, path, headers) {
			return route, nil
		}
	}
	return nil, apperrors.Wrap(apperrors.ErrCodeNotFound, "no route matched", ports.ErrNoRouteMatched)
}
