package container

import (
	"context"
	"fmt"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// Container holds all wired service dependencies.
type Container struct {
	Handler *inboundhttp.Handler
	closer  func()
}

// Close releases resources held by the container (e.g. database connection pool).
func (c *Container) Close() {
	if c.closer != nil {
		c.closer()
	}
}

// New creates and wires all dependencies.
// When cfg.Database.URL is non-empty, pending migrations are run and the
// PostgreSQL repository adapter is used. Otherwise, the in-memory adapter
// is selected so the service can run without an external database.
func New(ctx context.Context, cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "config is required")
	}
	if logger == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "logger is required")
	}

	clientRepo, closer, err := selectClientRepository(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	clientSvc := application.NewClientService(clientRepo)
	handler := inboundhttp.NewHandler(clientSvc, clientSvc, clientSvc, clientSvc, logger)

	return &Container{
		Handler: handler,
		closer:  closer,
	}, nil
}

// selectClientRepository returns a domain.ClientRepository and a closer function
// based on the configuration. The caller must invoke the closer when done.
func selectClientRepository(ctx context.Context, cfg *config.Config, logger logging.Logger) (domain.ClientRepository, func(), error) {
	if cfg.Database.URL == "" {
		logger.Info("database.url not set — using in-memory client repository")
		return memory.NewClientRepository(), func() {}, nil
	}

	logger.Info("database.url set — running migrations and connecting to postgres")

	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, func() {}, fmt.Errorf("running postgres migrations: %w", err)
	}

	repo, err := postgres.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to postgres: %w", err)
	}

	logger.Info("connected to postgres — using postgres client repository")
	return repo, repo.Close, nil
}
