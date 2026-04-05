package container

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/inbound/http"
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
// schema migrations, and uses the PostgreSQL user repository. When it is
// empty the container falls back to the in-memory repository, which is
// appropriate for local development and the reference implementation's
// zero-dependency mode. See ADR-0004 and ADR-0005.
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	userRepo, closer, err := buildUserRepository(cfg)
	if err != nil {
		return nil, fmt.Errorf("building user repository: %w", err)
	}

	hasher := application.NewBCryptHasher(bcrypt.DefaultCost)
	authSvc := application.NewAuthService(userRepo, hasher)
	handler := inboundhttp.NewHandler(authSvc, authSvc, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
		closer:  closer,
	}, nil
}

// buildUserRepository selects the user repository implementation based on
// whether a database URL is configured. PostgreSQL is preferred when available;
// in-memory is the fallback for zero-dependency local/dev usage.
// The returned closer must be called when the repository is no longer needed.
func buildUserRepository(cfg *config.Config) (domain.UserRepository, func(), error) {
	if cfg.Database.URL == "" {
		return memory.NewUserRepository(), func() {}, nil
	}

	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, func() {}, fmt.Errorf("running postgres migrations: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return nil, func() {}, fmt.Errorf("connecting to postgres: %w", err)
	}

	return postgres.NewUserRepository(pool), pool.Close, nil
}
