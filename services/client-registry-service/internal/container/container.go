// Package container wires the client-registry-service's dependencies
// through the platform DI container. Resolution from the returned container
// is restricted to the composition root in cmd/main.go and tests; business
// code receives its dependencies via constructor parameters.
package container

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/postgres"
	sqliteadapter "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/sqlite"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/observability"
)

// New constructs and bootstraps a platform container wired with every
// dependency this service needs.
//
// clientRepositoryProvider dispatches on cfg.Database.URL's scheme:
// "postgres://" (or "postgresql://") selects the PostgreSQL adapter,
// "sqlite:" or "file:" selects the SQLite adapter (local development and
// acceptance testing — no server process required), and an empty URL
// falls back to the in-memory adapter. Either database adapter's
// connection is registered as a close hook so Container.Close shuts it
// down cleanly.
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
	platform.Register(c, registrationServiceProvider)
	platform.Register(c, handlerProvider)
	platform.Register(c, registrationHandlerProvider)
	platform.Register(c, registrationManagementHandlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

func clientRepositoryProvider(ctx context.Context, c *platform.Container) (domain.ClientRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	switch {
	case cfg.Database.URL == "":
		log.Info("database.url not set — using in-memory client repository")
		return memory.NewClientRepository(), nil
	case isSQLiteDSN(cfg.Database.URL):
		return sqliteClientRepositoryProvider(ctx, c, cfg.Database.URL, log)
	default:
		return postgresClientRepositoryProvider(ctx, c, cfg.Database.URL, log)
	}
}

// isSQLiteDSN reports whether dsn should be routed to the SQLite adapter.
// modernc.org/sqlite accepts both "file:" and bare "sqlite:" DSNs; anything
// else (in practice, "postgres://" / "postgresql://") goes to postgres.
func isSQLiteDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "file:") || strings.HasPrefix(dsn, "sqlite:")
}

func postgresClientRepositoryProvider(ctx context.Context, c *platform.Container, dsn string, log logging.Logger) (domain.ClientRepository, error) {
	log.Info("database.url set — running migrations and connecting to postgres")
	if err := postgres.RunMigrations(dsn); err != nil {
		return nil, fmt.Errorf("running postgres migrations: %w", err)
	}
	repo, err := postgres.Connect(ctx, dsn)
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

// sqliteClientRepositoryProvider mirrors postgresClientRepositoryProvider
// for the SQLite adapter — same migration-then-connect shape, but
// RunMigrations needs its own short-lived *sql.DB since it isn't wrapped
// by the ClientRepository the way postgres's RunMigrations is (postgres's
// migrate library manages its own connection internally).
func sqliteClientRepositoryProvider(ctx context.Context, c *platform.Container, dsn string, log logging.Logger) (domain.ClientRepository, error) {
	log.Info("database.url set — running migrations and connecting to sqlite", "dsn", dsn)
	migrationDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database for migrations: %w", err)
	}
	if err := sqliteadapter.RunMigrations(ctx, migrationDB); err != nil {
		_ = migrationDB.Close()
		return nil, fmt.Errorf("running sqlite migrations: %w", err)
	}
	if err := migrationDB.Close(); err != nil {
		return nil, fmt.Errorf("closing sqlite migration connection: %w", err)
	}

	repo, err := sqliteadapter.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to sqlite: %w", err)
	}
	log.Info("connected to sqlite — using sqlite client repository")
	c.OnClose("sqlite", func(_ context.Context) error {
		return repo.Close()
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

// registrationServiceProvider wires the RFC 7591 dynamic-client
// registration service (ADR-0013). Returns nil when
// CLIENT_REGISTRATION_BASE_URL is unset — the handler provider treats a
// nil service as "DCR disabled".
func registrationServiceProvider(ctx context.Context, c *platform.Container) (*application.RegistrationService, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.Registration.PublicBaseURL == "" {
		return nil, nil
	}
	repo, err := platform.Resolve[domain.ClientRepository](ctx, c)
	if err != nil {
		return nil, err
	}
	emitter := platform.MustResolve[audit.Emitter](ctx, c)
	return application.NewRegistrationService(repo, application.RegistrationServiceConfig{
		PublicBaseURL:  cfg.Registration.PublicBaseURL,
		AllowedScopes:  cfg.Registration.AllowedScopes,
		AllowLocalhost: cfg.Registration.AllowLocalhost,
	}).WithAudit(emitter, "client-registry-service"), nil
}

// registrationHandlerProvider wires the RFC 7591 HTTP handler. Returns
// nil when DCR is disabled (see [registrationServiceProvider]); the
// router uses nil-resolution to skip /register.
func registrationHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.RegistrationHandler, error) {
	svc, _ := platform.Resolve[*application.RegistrationService](ctx, c)
	if svc == nil {
		return nil, nil
	}
	log := platform.MustResolve[logging.Logger](ctx, c)
	return inboundhttp.NewRegistrationHandler(svc, log), nil
}

// registrationManagementHandlerProvider wires the RFC 7592 management
// HTTP handler. Returns nil when DCR is disabled — the router uses
// nil-resolution to skip the GET/PUT/DELETE /register/{client_id}
// routes. Shares the underlying RegistrationService with the RFC 7591
// handler so the bearer token's bcrypt-compared hash is the same one
// the register response handed out.
func registrationManagementHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.RegistrationManagementHandler, error) {
	svc, _ := platform.Resolve[*application.RegistrationService](ctx, c)
	if svc == nil {
		return nil, nil
	}
	log := platform.MustResolve[logging.Logger](ctx, c)
	return inboundhttp.NewRegistrationManagementHandler(svc, log), nil
}
