package container

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/email"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Container holds all wired service dependencies.
type Container struct {
	Logger  logging.Logger
	Handler *inboundhttp.Handler
	Config  *config.Config
	closer  func()
}

// Close releases resources held by the container (e.g. the database connection pool).
// It is idempotent and safe to call more than once.
func (c *Container) Close() {
	if c.closer != nil {
		c.closer()
	}
}

// New creates and wires all dependencies.
//
// When cfg.Database.URL is set the container connects to PostgreSQL, runs
// schema migrations, and uses the PostgreSQL-backed repositories. When it is
// empty the container falls back to in-memory repositories, which is
// appropriate for local development and the reference implementation's
// zero-dependency mode. See ADR-0004 and ADR-0005.
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	repos, closer, err := buildRepositories(cfg)
	if err != nil {
		return nil, fmt.Errorf("building repositories: %w", err)
	}

	sender, err := buildEmailSender(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("building email sender: %w", err)
	}

	hasher := application.NewBCryptHasher(bcrypt.DefaultCost)
	authSvc := application.NewAuthService(repos.users, hasher)
	verifierSvc := application.NewEmailVerificationService(
		repos.users,
		repos.verificationTokens,
		sender,
		application.EmailVerificationConfig{
			TokenTTL:                time.Duration(cfg.Email.VerificationTokenTTLSeconds) * time.Second,
			VerificationURLTemplate: cfg.Email.VerificationURLTemplate,
		},
	)
	resetSvc := application.NewPasswordResetService(
		repos.users,
		repos.passwordResetTokens,
		sender,
		hasher,
		application.PasswordResetConfig{
			TokenTTL:         time.Duration(cfg.Email.PasswordResetTokenTTLSeconds) * time.Second,
			ResetURLTemplate: cfg.Email.PasswordResetURLTemplate,
		},
	)

	handler := inboundhttp.NewHandler(authSvc, authSvc, verifierSvc, resetSvc, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
		closer:  closer,
	}, nil
}

// repos bundles the three repository handles so the wiring stays readable.
type repos struct {
	users               domain.UserRepository
	verificationTokens  domain.VerificationTokenRepository
	passwordResetTokens domain.PasswordResetTokenRepository
}

// buildRepositories selects the repository backends based on whether a
// database URL is configured. PostgreSQL is preferred when available;
// in-memory is the fallback for zero-dependency local/dev usage.
// The returned closer must be called when the repositories are no longer needed.
func buildRepositories(cfg *config.Config) (repos, func(), error) {
	if cfg.Database.URL == "" {
		return repos{
			users:               memory.NewUserRepository(),
			verificationTokens:  memory.NewVerificationTokenRepository(),
			passwordResetTokens: memory.NewPasswordResetTokenRepository(),
		}, func() {}, nil
	}

	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return repos{}, func() {}, fmt.Errorf("running postgres migrations: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return repos{}, func() {}, fmt.Errorf("connecting to postgres: %w", err)
	}

	return repos{
		users:               postgres.NewUserRepository(pool),
		verificationTokens:  postgres.NewVerificationTokenRepository(pool),
		passwordResetTokens: postgres.NewPasswordResetTokenRepository(pool),
	}, pool.Close, nil
}

// buildEmailSender selects an email-sender adapter based on the EmailConfig.
// stdout is the default; noop drops messages silently. Unknown senders are
// rejected at startup so misconfiguration surfaces immediately.
func buildEmailSender(cfg *config.Config, logger logging.Logger) (domain.EmailSender, error) {
	switch cfg.Email.Sender {
	case "", "stdout":
		return email.NewStdoutSender(logger), nil
	case "noop":
		return email.NewNoopSender(), nil
	default:
		return nil, fmt.Errorf("unknown email sender %q (want: stdout | noop)", cfg.Email.Sender)
	}
}
