// Package container wires the token-introspection-service's dependencies
// through the platform DI container. Resolution from the returned container
// is restricted to the composition root in cmd/main.go and tests; business
// code receives its dependencies via constructor parameters.
package container

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/audit"
	platform "github.com/jedi-knights/go-platform/container"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/inbound/http"
	jwksadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/jwks"
	jwtadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/jwt"
	redisadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/observability"
)

// auditEmitterProvider builds the audit.Emitter per ADR-0018 + ADR-0019.
// When INTROSPECT_AUDIT_DURABLE_DSN is set the emitter writes through a
// Postgres durable sink in addition to the best-effort stderr sink, and
// the returned pool is registered as an OnClose hook for graceful
// shutdown.
func auditEmitterProvider(ctx context.Context, c *platform.Container) (audit.Emitter, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	wiring, err := observability.NewAuditEmitter(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if wiring.Pool != nil {
		pool := wiring.Pool
		c.OnClose("audit-durable", func(_ context.Context) error {
			pool.Close()
			return nil
		})
	}
	return wiring.Emitter, nil
}

// tokenValidatorProvider builds the right TokenValidator for the configured
// path. JWKS-backed RS256 takes precedence over the legacy HS256 signing key;
// extracted from the inline closure so New() stays under the cyclomatic
// complexity cap.
func tokenValidatorProvider(ctx context.Context, c *platform.Container) (domain.TokenValidator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.JWT.JWKSURL != "" {
		ttl := parseJWKSCacheTTL(cfg.JWT.JWKSCacheTTL)
		log.Info("using JWKS-backed RS256 validation", "url", cfg.JWT.JWKSURL, "cache_ttl", ttl)
		// otelhttp.NewTransport wraps the JWKS fetch so every outbound
		// request becomes a client span and carries the W3C
		// traceparent header. The wrapper is inert when tracing is
		// disabled — no spans are emitted but header propagation still
		// runs, which is the correct behaviour for a no-op
		// TracerProvider.
		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		}
		fetcher := jwksadapter.NewFetcher(cfg.JWT.JWKSURL,
			jwksadapter.WithCacheTTL(ttl),
			jwksadapter.WithHTTPClient(httpClient),
		)
		return jwtadapter.NewRS256Validator(fetcher.KeyByID, cfg.JWT.Issuer), nil
	}
	log.Info("using HS256 signing-key validation (legacy path; set INTROSPECT_JWT_JWKS_URL for RS256)")
	return jwtadapter.NewValidator([]byte(cfg.JWT.SigningKey), cfg.JWT.Issuer), nil
}

// parseJWKSCacheTTL falls back to 1h on any parse failure — operators should
// set a Go-duration string like "1h" or "30m"; anything else degrades quietly
// rather than refusing to start.
func parseJWKSCacheTTL(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return time.Hour
	}
	return d
}

// redisAddr extracts the host:port from a Redis URL so it can be logged
// safely — the raw URL may embed a password (redis://:pass@host/db).
func redisAddr(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

// New constructs and bootstraps a platform container wired with every
// dependency this service needs.
//
// When cfg.Redis.URL is set, a Redis-backed revocation checker is wired in;
// otherwise the revocation check is disabled and tokens are accepted until
// their JWT expiry. The Redis client is NOT pinged at startup so transient
// Redis unavailability does not block the service from starting (the
// revocation check fails closed at request time per RFC 7662 §2.2).
func New(ctx context.Context, cfg *config.Config, logger logging.Logger) (*platform.Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	c := platform.New()

	platform.Register(c, func(_ context.Context, _ *platform.Container) (*config.Config, error) {
		return cfg, nil
	})
	platform.Register(c, func(_ context.Context, _ *platform.Container) (logging.Logger, error) {
		return logger, nil
	})

	platform.Register(c, func(ctx context.Context, c *platform.Container) (domain.RevocationChecker, error) {
		cfg := platform.MustResolve[*config.Config](ctx, c)
		log := platform.MustResolve[logging.Logger](ctx, c)
		if cfg.Redis.URL == "" {
			log.Info("Redis revocation check disabled (INTROSPECT_REDIS_URL not set); revoked tokens will be accepted until expiry")
			return nil, nil
		}
		log.Info("using Redis revocation check", "addr", redisAddr(cfg.Redis.URL))
		client, err := redisadapter.NewClient(cfg.Redis.URL)
		if err != nil {
			return nil, fmt.Errorf("connecting to Redis: %w", err)
		}
		return redisadapter.NewRevocationStore(client), nil
	})

	platform.Register(c, tokenValidatorProvider)

	platform.Register(c, auditEmitterProvider)

	platform.Register(c, func(ctx context.Context, c *platform.Container) (*application.IntrospectionService, error) {
		validator := platform.MustResolve[domain.TokenValidator](ctx, c)
		// Revocation may be nil when Redis is unconfigured; IntrospectionService
		// handles nil safely by skipping the revocation step.
		revocation, err := platform.Resolve[domain.RevocationChecker](ctx, c)
		if err != nil {
			return nil, err
		}
		emitter := platform.MustResolve[audit.Emitter](ctx, c)
		return application.NewIntrospectionService(validator, revocation).
			WithAudit(emitter, "token-introspection-service"), nil
	})

	platform.Register(c, func(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
		svc := platform.MustResolve[*application.IntrospectionService](ctx, c)
		cfg := platform.MustResolve[*config.Config](ctx, c)
		log := platform.MustResolve[logging.Logger](ctx, c)
		return inboundhttp.NewHandler(svc, log, cfg.Introspection.Secret), nil
	})

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}
