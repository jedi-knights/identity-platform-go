package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// RouteResolver is the outbound port for route lookup.
// Implementations are responsible for finding the best matching route given an
// inbound request's attributes. The resolution strategy (static config, service
// registry, DNS, etc.) is an implementation detail hidden behind this interface.
//
// Resolve must return ErrNoRouteMatched (wrapped in an AppError) when no route
// matches, and any other error only for genuine infrastructure failures.
type RouteResolver interface {
	Resolve(ctx context.Context, method, path string, headers map[string]string) (*domain.Route, error)
}
