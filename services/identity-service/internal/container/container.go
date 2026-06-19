// Package container wires the identity-service's dependencies through the
// platform DI container. Resolution from the returned container is
// restricted to the composition root in cmd/main.go and tests; business
// code receives its dependencies via constructor parameters.
package container

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	platform "github.com/jedi-knights/go-platform/container"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/email"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// New constructs and bootstraps a platform container wired with every
// dependency this service needs.
//
// When cfg.Database.URL is set the container connects to PostgreSQL, runs
// schema migrations, and uses the PostgreSQL-backed repositories; the pool
// is registered as an OnClose hook. When the URL is empty the container
// falls back to in-memory repositories — appropriate for local development
// and the reference implementation's zero-dependency mode (ADR-0004 and
// ADR-0005).
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
	platform.Register(c, emailSenderProvider)
	platform.Register(c, hasherProvider)
	platform.Register(c, authServiceProvider)
	platform.Register(c, emailVerificationServiceProvider)
	platform.Register(c, handlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

// repositories bundles the user and verification-token repos into a single
// eager registration so they can share a connection pool when postgres is
// configured.
type repositories struct {
	user  domain.UserRepository
	token domain.VerificationTokenRepository
}

func repositoriesProvider(ctx context.Context, c *platform.Container) (*repositories, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.Database.URL == "" {
		return &repositories{
			user:  memory.NewUserRepository(),
			token: memory.NewVerificationTokenRepository(),
		}, nil
	}

	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, fmt.Errorf("running postgres migrations: %w", err)
	}

	// Bound the connect operation independently of the caller's context so a
	// hung postgres dial cannot indefinitely block startup. This matches the
	// 10s budget from the prior implementation.
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, err := postgres.Connect(connectCtx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	c.OnClose("postgres", func(_ context.Context) error {
		pool.Close()
		return nil
	})
	return &repositories{
		user:  postgres.NewUserRepository(pool),
		token: postgres.NewVerificationTokenRepository(pool),
	}, nil
}

// emailSenderProvider selects an email-sender adapter based on
// cfg.Email.Sender. stdout is the default; noop drops messages silently.
// Unknown senders are rejected at startup so misconfiguration surfaces
// immediately.
func emailSenderProvider(ctx context.Context, c *platform.Container) (domain.EmailSender, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	switch cfg.Email.Sender {
	case "", "stdout":
		return email.NewStdoutSender(log), nil
	case "noop":
		return email.NewNoopSender(), nil
	default:
		return nil, fmt.Errorf("unknown email sender %q (want: stdout | noop)", cfg.Email.Sender)
	}
}

func hasherProvider(context.Context, *platform.Container) (domain.PasswordHasher, error) {
	return application.NewBCryptHasher(bcrypt.DefaultCost), nil
}

func authServiceProvider(ctx context.Context, c *platform.Container) (*application.AuthService, error) {
	repos := platform.MustResolve[*repositories](ctx, c)
	hasher := platform.MustResolve[domain.PasswordHasher](ctx, c)
	return application.NewAuthService(repos.user, hasher), nil
}

func emailVerificationServiceProvider(ctx context.Context, c *platform.Container) (*application.EmailVerificationService, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	repos := platform.MustResolve[*repositories](ctx, c)
	sender := platform.MustResolve[domain.EmailSender](ctx, c)
	return application.NewEmailVerificationService(
		repos.user,
		repos.token,
		sender,
		application.EmailVerificationConfig{
			TokenTTL:                time.Duration(cfg.Email.TokenTTLSeconds) * time.Second,
			VerificationURLTemplate: cfg.Email.VerificationURLTemplate,
		},
	), nil
}

func handlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	authSvc := platform.MustResolve[*application.AuthService](ctx, c)
	verifierSvc := platform.MustResolve[*application.EmailVerificationService](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	return inboundhttp.NewHandler(authSvc, authSvc, verifierSvc, log), nil
}
