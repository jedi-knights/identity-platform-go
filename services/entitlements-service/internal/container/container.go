// Package container wires the entitlements-service dependency graph
// via go-platform/container. This is the composition root — every
// concrete type is chosen here, and platform.Resolve is used only in
// this package and in cmd/main.go.
package container

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/audit"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/observability"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// New constructs the entitlements-service container, registers all
// providers, and bootstraps eager registrations. Returns the container
// ready for use at the composition root.
func New(ctx context.Context, cfg *config.Config, log logging.Logger) (*platform.Container, error) {
	if cfg == nil || log == nil {
		return nil, fmt.Errorf("container: cfg and log are required")
	}

	c := platform.New()

	platform.Register(c, func(_ context.Context, _ *platform.Container) (*config.Config, error) {
		return cfg, nil
	})
	platform.Register(c, func(_ context.Context, _ *platform.Container) (logging.Logger, error) {
		return log, nil
	})
	platform.Register(c, auditEmitterProvider)
	platform.Register(c, accountRepoProvider)
	platform.Register(c, accountServiceProvider)
	platform.Register(c, httpHandlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

// auditEmitterProvider builds the audit.Emitter per ADR-0018 + ADR-0019.
// When ENTITLEMENTS_AUDIT_DURABLE_DSN is set the emitter writes through
// a Postgres durable sink; otherwise it falls back to stderr-only.
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

// accountRepoProvider selects the account repository. When
// ENTITLEMENTS_DATABASE_URL is set the Postgres adapter is wired and
// the connection pool is registered as an OnClose hook so shutdown
// drains cleanly. When unset the in-memory adapter is used — fine for
// development, unsafe for anything that must survive a restart.
func accountRepoProvider(ctx context.Context, c *platform.Container) (ports.AccountRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Database.URL == "" {
		log.Info("account repository: using in-memory adapter (ENTITLEMENTS_DATABASE_URL not set)")
		return memory.NewAccountRepository(), nil
	}
	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, fmt.Errorf("account repository: running migrations: %w", err)
	}
	pool, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("account repository: connecting to postgres: %w", err)
	}
	c.OnClose("account-repo-pool", func(_ context.Context) error {
		pool.Close()
		return nil
	})
	log.Info("account repository: using postgres adapter", "database_url_configured", true)
	return postgres.NewAccountRepository(pool), nil
}

// accountServiceProvider wires the application-layer service against
// its repository + audit emitter.
func accountServiceProvider(ctx context.Context, c *platform.Container) (*application.AccountService, error) {
	repo := platform.MustResolve[ports.AccountRepository](ctx, c)
	emitter := platform.MustResolve[audit.Emitter](ctx, c)
	return application.NewAccountService(repo).WithAudit(emitter, "entitlements-service"), nil
}

// httpHandlerProvider wires the inbound HTTP adapter.
func httpHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	svc := platform.MustResolve[*application.AccountService](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	return inboundhttp.NewHandler(svc, log), nil
}
