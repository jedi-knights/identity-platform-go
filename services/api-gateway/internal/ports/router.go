package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// RequestRouter is the primary inbound application port for the gateway use case.
// HTTP handlers depend on this interface — never on the concrete GatewayService type.
//
// Route resolves the upstream route for an inbound request. It returns
// ErrNoRouteMatched (via the error chain) when no route is configured for the
// request, and a non-nil AppError for infrastructure failures.
type RequestRouter interface {
	Route(ctx context.Context, method, path string, headers map[string]string) (*domain.Route, error)
}
