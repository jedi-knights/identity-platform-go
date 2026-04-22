package application

import (
	"sort"
	"strings"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// RouteResolver resolves request paths to backend routes using longest-prefix matching.
type RouteResolver struct {
	routes []domain.Route
}

// NewRouteResolver creates a resolver from the given routes.
// Routes are sorted by prefix length descending so that longest-prefix-wins.
func NewRouteResolver(routes []domain.Route) *RouteResolver {
	sorted := make([]domain.Route, len(routes))
	copy(sorted, routes)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].Match.PathPrefix) > len(sorted[j].Match.PathPrefix)
	})
	return &RouteResolver{routes: sorted}
}

// Resolve finds the first route whose prefix matches the given path.
func (r *RouteResolver) Resolve(path string) (*domain.Route, bool) {
	for i := range r.routes {
		if strings.HasPrefix(path, r.routes[i].Match.PathPrefix) {
			return &r.routes[i], true
		}
	}
	return nil, false
}
