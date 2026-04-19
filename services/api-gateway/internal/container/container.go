package container

import (
	"context"
	"fmt"
	"net/http"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/healthhttp"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/application"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Container holds all wired service dependencies.
type Container struct {
	Logger      logging.Logger
	Handler     *inboundhttp.Handler
	RateLimiter ports.RateLimiter
	Config      *config.Config
}

// New creates and wires all dependencies. The ctx controls the lifetime of
// background goroutines (e.g., rate limiter eviction).
func New(ctx context.Context, cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "config is required")
	}

	// Build domain routes from config.
	routes := buildRoutes(cfg)

	// Application layer.
	resolver := application.NewRouteResolver(routes)

	// Outbound adapters.
	healthClient := &http.Client{Timeout: 2 * time.Second}
	healthChecker := healthhttp.NewChecker(healthClient)
	healthAgg := application.NewHealthAggregator(healthChecker, routes)

	rateLimiter := memory.NewRateLimiter(ctx, domain.RateLimitRule{
		RequestsPerSecond: cfg.RateLimit.RequestsPerSecond,
		BurstSize:         cfg.RateLimit.BurstSize,
	})

	// Inbound adapters.
	proxyMap, err := inboundhttp.NewProxyMap(routes)
	if err != nil {
		return nil, fmt.Errorf("building proxy map: %w", err)
	}
	handler := inboundhttp.NewHandler(resolver, proxyMap, healthAgg, logger)

	logger.Info("api-gateway wired",
		"routes", len(routes),
		"rate_limit_rps", cfg.RateLimit.RequestsPerSecond,
		"rate_limit_burst", cfg.RateLimit.BurstSize,
	)

	return &Container{
		Logger:      logger,
		Handler:     handler,
		RateLimiter: rateLimiter,
		Config:      cfg,
	}, nil
}

// buildRoutes converts config route entries to domain routes.
func buildRoutes(cfg *config.Config) []domain.Route {
	routes := make([]domain.Route, len(cfg.Routes))
	for i, rc := range cfg.Routes {
		routes[i] = domain.Route{
			PathPrefix:  rc.PathPrefix,
			BackendURL:  rc.BackendURL,
			StripPrefix: rc.StripPrefix,
		}
	}
	return routes
}
