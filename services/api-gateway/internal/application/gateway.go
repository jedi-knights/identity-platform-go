package application

import (
	"context"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// GatewayService is the core application use case: resolve an inbound request to its
// upstream route. It wraps a RouteResolver with structured logging and error classification.
//
// GatewayService implements ports.RequestRouter so that inbound HTTP adapters depend on
// the port interface rather than this concrete type — enabling independent testing of
// both layers.
type GatewayService struct {
	resolver ports.RouteResolver
	logger   logging.Logger
}

// Compile-time check: GatewayService must satisfy the RequestRouter port.
var _ ports.RequestRouter = (*GatewayService)(nil)

// NewGatewayService creates a GatewayService that resolves routes using resolver
// and logs decisions via logger.
func NewGatewayService(resolver ports.RouteResolver, logger logging.Logger) *GatewayService {
	return &GatewayService{
		resolver: resolver,
		logger:   logger,
	}
}

// Route resolves the upstream route for an inbound request.
//
// It returns ErrNoRouteMatched (in the error chain) when no configured route matches
// the request — callers should surface this as an HTTP 404.
// Any other error indicates a resolver infrastructure failure and should be treated
// as an HTTP 500.
func (s *GatewayService) Route(ctx context.Context, method, path string, headers map[string]string) (*domain.Route, error) {
	route, err := s.resolver.Resolve(ctx, method, path, headers)
	if err != nil {
		if apperrors.IsNotFound(err) {
			s.logger.With("method", method, "path", path).
				Debug("no route matched")
		} else {
			s.logger.With("method", method, "path", path).
				Error("route resolution failed", "error", err)
		}
		return nil, err
	}

	s.logger.With("method", method, "path", path, "route", route.Name).
		Debug("route resolved")

	return route, nil
}
