package container

import (
	"context"
	"fmt"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/postgres"
	redisadapter "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/ports"
)

// Container holds all wired dependencies for the authorization-policy-service.
type Container struct {
	Logger  logging.Logger
	Handler *inboundhttp.Handler
	Config  *config.Config
	closer  func() // called by Close to release external connections
}

// Close releases any external connections (PostgreSQL pool, Redis client) opened
// during New. Safe to call multiple times. Must be called after the HTTP server
// has shut down to avoid in-flight query cancellation.
func (c *Container) Close() {
	if c.closer != nil {
		c.closer()
	}
}

// New wires up the service dependencies and returns a ready-to-use Container.
// ctx is passed to the database connection so startup can be cancelled.
//
// When cfg.Database.URL is non-empty, schema migrations are applied and
// PostgreSQL-backed repositories are used. Otherwise the service falls back
// to in-memory adapters so it can run without an external database during
// local development.
//
// When cfg.Redis.URL is non-empty, a CachingPolicyEvaluator wraps the
// PolicyService to cache evaluation results in Redis with a 60-second TTL.
// If Redis is unavailable or its URL is empty, evaluations go directly to
// the backing store.
func New(ctx context.Context, cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "config is required")
	}
	if logger == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "logger is required")
	}

	policyRepo, roleRepo, repoCloser, err := buildRepos(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	policyService := application.NewPolicyService(policyRepo, roleRepo)

	evaluator, redisCloser, err := buildEvaluator(ctx, cfg, logger, policyService)
	if err != nil {
		repoCloser()
		return nil, err
	}

	handler := inboundhttp.NewHandler(evaluator, policyService, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
		closer: func() {
			redisCloser()
			repoCloser()
		},
	}, nil
}

// buildRepos selects the policy and role repository adapters.
// Uses PostgreSQL when cfg.Database.URL is set; falls back to in-memory for local dev.
// Returns a closer that must be called when the repositories are no longer needed.
func buildRepos(ctx context.Context, cfg *config.Config, logger logging.Logger) (domain.PolicyRepository, domain.RoleRepository, func(), error) {
	noop := func() {}
	if cfg.Database.URL == "" {
		return memory.NewPolicyRepository(), memory.NewRoleRepository(), noop, nil
	}
	logger.Info("using PostgreSQL policy store", "url", cfg.Database.URL)
	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, nil, noop, fmt.Errorf("running database migrations: %w", err)
	}
	pool, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return nil, nil, noop, fmt.Errorf("connecting to database: %w", err)
	}
	return postgres.NewPolicyRepository(pool), postgres.NewRoleRepository(pool), pool.Close, nil
}

// buildEvaluator wraps policyService with a Redis cache when cfg.Redis.URL is set.
// Returns the evaluator and a closer for the Redis client.
func buildEvaluator(_ context.Context, cfg *config.Config, logger logging.Logger, policyService *application.PolicyService) (ports.PolicyEvaluator, func(), error) {
	noop := func() {}
	if cfg.Redis.URL == "" {
		return policyService, noop, nil
	}
	logger.Info("using Redis policy cache", "url", cfg.Redis.URL)
	redisClient, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, noop, fmt.Errorf("connecting to redis: %w", err)
	}
	evaluator := redisadapter.NewCachingPolicyEvaluator(policyService, redisClient, 60*time.Second, logger)
	return evaluator, func() { _ = redisClient.Close() }, nil
}
