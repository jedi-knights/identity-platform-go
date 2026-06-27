// Package container wires the client-registry-service's dependencies
// through the platform DI container. Resolution from the returned container
// is restricted to the composition root in cmd/main.go and tests; business
// code receives its dependencies via constructor parameters.
package container

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/observability"
)

// New constructs and bootstraps a platform container wired with every
// dependency this service needs.
//
// When cfg.Database.URL is set, pending migrations are run and the PostgreSQL
// repository adapter is used; the connection pool is registered as a close
// hook so Container.Close shuts it down cleanly. When the URL is empty the
// in-memory adapter is selected so the service can run without an external
// database.
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
	platform.Register(c, clientRepositoryProvider)
	platform.Register(c, auditEmitterProvider)
	platform.Register(c, clientServiceProvider)
	platform.Register(c, handlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

func clientRepositoryProvider(ctx context.Context, c *platform.Container) (domain.ClientRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Database.URL == "" {
		log.Info("database.url not set — using in-memory client repository")
		return memory.NewClientRepository(), nil
	}

	log.Info("database.url set — running migrations and connecting to postgres")
	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, fmt.Errorf("running postgres migrations: %w", err)
	}
	repo, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	log.Info("connected to postgres — using postgres client repository")
	c.OnClose("postgres", func(_ context.Context) error {
		repo.Close()
		return nil
	})
	return repo, nil
}

// auditEmitterProvider builds the audit.Emitter per ADR-0018 + ADR-0019.
// When CLIENT_AUDIT_DURABLE_DSN is set the emitter writes through a
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

func clientServiceProvider(ctx context.Context, c *platform.Container) (*application.ClientService, error) {
	repo, err := platform.Resolve[domain.ClientRepository](ctx, c)
	if err != nil {
		return nil, err
	}
	emitter := platform.MustResolve[audit.Emitter](ctx, c)
	return application.NewClientService(repo).WithAudit(emitter, "client-registry-service"), nil
}

func handlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	svc := platform.MustResolve[*application.ClientService](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	return inboundhttp.NewHandler(svc, svc, svc, svc, log), nil
}
