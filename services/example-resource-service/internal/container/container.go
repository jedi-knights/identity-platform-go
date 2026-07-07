// Package container wires the example-resource-service's dependencies
// through the platform DI container. Resolution from the returned container
// is restricted to the composition root in cmd/main.go and tests; business
// code receives its dependencies via constructor parameters.
package container

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	platform "github.com/jedi-knights/go-platform/container"
	"github.com/jedi-knights/go-platform/jwtutil"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/introspection"
	jwksadapter "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/jwks"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/memory"
	policyadapter "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/policy"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// New constructs and bootstraps a platform container wired with every
// dependency this service needs.
//
// Adapter selection:
//   - ResourceRepository: PostgreSQL adapter when RESOURCE_DATABASE_URL is
//     set, in-memory adapter otherwise. The postgres pool is registered as
//     an OnClose hook.
//   - TokenIntrospector: HTTP adapter (token-introspection-service) when
//     RESOURCE_INTROSPECTION_URL is set; otherwise nil, which causes the
//     router to fall back to local JWT validation. In the fallback path,
//     revoked tokens remain valid until expiry.
//   - PolicyChecker: HTTP adapter when RESOURCE_POLICY_URL is set;
//     otherwise nil, which disables the policy layer and lets scope alone
//     gate access.
func New(ctx context.Context, cfg *config.Config, logger logging.Logger) (*platform.Container, error) {
	if cfg == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "config is required")
	}
	if logger == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "logger is required")
	}

	c := platform.New()

	platform.Register(c, func(_ context.Context, _ *platform.Container) (*config.Config, error) {
		return cfg, nil
	})
	platform.Register(c, func(_ context.Context, _ *platform.Container) (logging.Logger, error) {
		return logger, nil
	})
	platform.Register(c, httpClientProvider)
	platform.Register(c, resourceRepositoryProvider)
	platform.Register(c, resourceServiceProvider)
	platform.Register(c, introspectorProvider)
	platform.Register(c, keySourceProvider)
	platform.Register(c, policyCheckerProvider)
	platform.Register(c, handlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

// httpClientProvider builds the single shared HTTP client used by every
// outbound adapter (introspection, policy, JWKS). otelhttp.NewTransport
// wraps the default transport so every outbound request becomes a client
// span and carries the W3C traceparent header. The wrapper is inert when
// tracing is disabled — no spans are emitted but header propagation still
// runs, which is the correct behaviour for a no-op TracerProvider.
func httpClientProvider(context.Context, *platform.Container) (*http.Client, error) {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}, nil
}

func resourceRepositoryProvider(ctx context.Context, c *platform.Container) (domain.ResourceRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Database.URL == "" {
		log.Info("RESOURCE_DATABASE_URL not set; using in-memory resource repository")
		return memory.NewResourceRepository(), nil
	}

	log.Info("running database migrations", "url", cfg.Database.URL)
	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, fmt.Errorf("running resource migrations: %w", err)
	}
	pool, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	c.OnClose("postgres", func(_ context.Context) error {
		pool.Close()
		return nil
	})
	log.Info("using PostgreSQL resource repository")
	return postgres.NewResourceRepository(pool), nil
}

func resourceServiceProvider(ctx context.Context, c *platform.Container) (*application.ResourceService, error) {
	repo, err := platform.Resolve[domain.ResourceRepository](ctx, c)
	if err != nil {
		return nil, err
	}
	return application.NewResourceService(repo), nil
}

func introspectorProvider(ctx context.Context, c *platform.Container) (ports.TokenIntrospector, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Introspection.URL == "" {
		log.Info("using local JWT validation (RESOURCE_INTROSPECTION_URL not set); revoked tokens will not be rejected until expiry")
		return nil, nil
	}
	log.Info("using remote token-introspection-service", "url", cfg.Introspection.URL)
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	return introspection.NewClient(cfg.Introspection.URL, httpClient, cfg.Introspection.Secret), nil
}

// keySourceProvider builds a JWKS-backed jwtutil.KeySource when
// RESOURCE_JWT_JWKS_URL is set. Returns nil otherwise — the router uses nil
// to fall through to the HS256 path. Skipped (returns nil) when introspection
// is configured, since introspection wins in the router's selection order.
func keySourceProvider(ctx context.Context, c *platform.Container) (jwtutil.KeySource, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Introspection.URL != "" || cfg.JWT.JWKSURL == "" {
		return nil, nil
	}
	ttl := parseJWKSCacheTTL(cfg.JWT.JWKSCacheTTL)
	log.Info("using JWKS-backed local RS256 validation", "url", cfg.JWT.JWKSURL, "cache_ttl", ttl)
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	fetcher := jwksadapter.NewFetcher(cfg.JWT.JWKSURL,
		jwksadapter.WithCacheTTL(ttl),
		jwksadapter.WithHTTPClient(httpClient),
	)
	return fetcher.KeyByID, nil
}

// parseJWKSCacheTTL falls back to 1h on parse failure — operators should set
// a Go-duration string ("1h", "30m"); anything else degrades quietly.
func parseJWKSCacheTTL(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return time.Hour
	}
	return d
}

func policyCheckerProvider(ctx context.Context, c *platform.Container) (ports.PolicyChecker, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Policy.URL == "" {
		log.Info("RESOURCE_POLICY_URL not set; policy evaluation skipped, scope alone gates access")
		return nil, nil
	}
	log.Info("using remote authorization-policy-service", "url", cfg.Policy.URL)
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	return policyadapter.New(cfg.Policy.URL, policyadapter.WithHTTPClient(httpClient)), nil
}

func handlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	svc := platform.MustResolve[*application.ResourceService](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	policyChecker := platform.MustResolve[ports.PolicyChecker](ctx, c)
	return inboundhttp.NewHandler(svc, svc, svc, log, policyChecker), nil
}
