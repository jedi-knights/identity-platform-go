// Package container wires the authorization-policy-service's dependencies
// through the platform DI container. Resolution from the returned container
// is restricted to the composition root in cmd/main.go and tests; business
// code receives its dependencies via constructor parameters.
package container

import (
	"context"
	"fmt"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/postgres"
	redisadapter "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/observability"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/ports"
)

// New constructs and bootstraps a platform container wired with every
// dependency this service needs.
//
// When cfg.Database.URL is non-empty, schema migrations are applied and
// PostgreSQL-backed repositories are used; the connection pool is registered
// as a close hook. Otherwise the service falls back to in-memory adapters so
// it can run without an external database during local development.
//
// When cfg.Redis.URL is non-empty, a CachingPolicyEvaluator wraps the
// PolicyService to cache evaluation results in Redis with a 60-second TTL;
// the Redis client is registered as a close hook.
//
// Close-order semantics match the prior implementation: Redis closes before
// the database pool. The platform container runs close hooks in LIFO, so
// the repositories are registered before the evaluator and the resulting
// shutdown order is redis → postgres.
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
	platform.Register(c, repositoriesProvider)
	platform.Register(c, auditEmitterProvider)
	platform.Register(c, policyServiceProvider)
	platform.Register(c, evaluatorProvider)
	platform.Register(c, handlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

// repositories bundles the policy and role repositories so they share a
// single eager registration — both come from the same connection pool when
// postgres is configured, and a single close hook drains that pool.
type repositories struct {
	policy domain.PolicyRepository
	role   domain.RoleRepository
}

func repositoriesProvider(ctx context.Context, c *platform.Container) (*repositories, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Database.URL == "" {
		return &repositories{
			policy: memory.NewPolicyRepository(),
			role:   memory.NewRoleRepository(),
		}, nil
	}
	log.Info("using PostgreSQL policy store", "url", cfg.Database.URL)
	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, fmt.Errorf("running database migrations: %w", err)
	}
	pool, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	// Registered first so it runs LAST on shutdown — matches the original
	// closer chain that closed Redis before the pool.
	c.OnClose("postgres", func(_ context.Context) error {
		pool.Close()
		return nil
	})
	return &repositories{
		policy: postgres.NewPolicyRepository(pool),
		role:   postgres.NewRoleRepository(pool),
	}, nil
}

// auditEmitterProvider builds the audit.Emitter per ADR-0018 + ADR-0019.
// When POLICY_AUDIT_DURABLE_DSN is set the emitter writes through a
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

func policyServiceProvider(ctx context.Context, c *platform.Container) (*application.PolicyService, error) {
	repos, err := platform.Resolve[*repositories](ctx, c)
	if err != nil {
		return nil, err
	}
	emitter := platform.MustResolve[audit.Emitter](ctx, c)
	return application.NewPolicyService(repos.policy, repos.role).
		WithAudit(emitter, "authorization-policy-service"), nil
}

func evaluatorProvider(ctx context.Context, c *platform.Container) (ports.PolicyEvaluator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	svc := platform.MustResolve[*application.PolicyService](ctx, c)
	if cfg.Redis.URL == "" {
		return svc, nil
	}
	log.Info("using Redis policy cache", "url", cfg.Redis.URL)
	redisClient, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to redis: %w", err)
	}
	// Registered after the postgres hook so it runs FIRST on shutdown —
	// matches the original closer chain.
	c.OnClose("redis", func(_ context.Context) error {
		_ = redisClient.Close()
		return nil
	})
	return redisadapter.NewCachingPolicyEvaluator(svc, redisClient, 60*time.Second, log), nil
}

func handlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	evaluator, err := platform.Resolve[ports.PolicyEvaluator](ctx, c)
	if err != nil {
		return nil, err
	}
	svc := platform.MustResolve[*application.PolicyService](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	return inboundhttp.NewHandler(evaluator, svc, log), nil
}
