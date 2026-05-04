package container

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/introspection"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/memory"
	policyadapter "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/policy"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/postgres"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// Container holds the wired dependencies for the example-resource-service.
type Container struct {
	Logger        logging.Logger
	Handler       *inboundhttp.Handler
	Config        *config.Config
	SigningKey    []byte
	Audience      string
	Issuer        string
	Introspector  ports.TokenIntrospector
	PolicyChecker ports.PolicyChecker
	closer        func()
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
// Adapter selection:
//   - ResourceRepository: PostgreSQL adapter when RESOURCE_DATABASE_URL is set;
//     in-memory adapter otherwise (suitable for local dev and unit testing).
//   - TokenIntrospector: HTTP adapter (token-introspection-service) when
//     RESOURCE_INTROSPECTION_URL is set; nil otherwise, which causes NewRouter
//     to fall back to local JWT validation. In the fallback path, revoked tokens
//     remain valid until expiry.
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	repo, closer, err := selectResourceRepository(cfg, logger)
	if err != nil {
		return nil, err
	}

	svc := application.NewResourceService(repo)

	var introspector ports.TokenIntrospector
	if cfg.Introspection.URL != "" {
		logger.Info("using remote token-introspection-service", "url", cfg.Introspection.URL)
		introspector = introspection.NewClient(cfg.Introspection.URL, &http.Client{Timeout: 5 * time.Second}, cfg.Introspection.Secret)
	} else {
		logger.Info("using local JWT validation (RESOURCE_INTROSPECTION_URL not set); revoked tokens will not be rejected until expiry")
	}

	var policyChecker ports.PolicyChecker
	if cfg.Policy.URL != "" {
		logger.Info("using remote authorization-policy-service", "url", cfg.Policy.URL)
		policyChecker = policyadapter.New(cfg.Policy.URL)
	} else {
		logger.Info("RESOURCE_POLICY_URL not set; policy evaluation skipped, scope alone gates access")
	}

	handler := inboundhttp.NewHandler(svc, svc, svc, logger, policyChecker)

	return &Container{
		Logger:        logger,
		Handler:       handler,
		Config:        cfg,
		SigningKey:    []byte(cfg.JWT.SigningKey),
		Audience:      cfg.JWT.Audience,
		Issuer:        cfg.JWT.Issuer,
		Introspector:  introspector,
		PolicyChecker: policyChecker,
		closer:        closer,
	}, nil
}

// selectResourceRepository returns a PostgreSQL-backed repository when
// RESOURCE_DATABASE_URL is set, otherwise falls back to the in-memory adapter.
// Migrations are run automatically before the connection pool is opened so
// the schema is always up to date at startup.
// The returned closer must be called when the repository is no longer needed.
func selectResourceRepository(cfg *config.Config, logger logging.Logger) (domain.ResourceRepository, func(), error) {
	if cfg.Database.URL == "" {
		logger.Info("RESOURCE_DATABASE_URL not set; using in-memory resource repository")
		return memory.NewResourceRepository(), func() {}, nil
	}

	logger.Info("running database migrations", "url", cfg.Database.URL)
	if err := postgres.RunMigrations(cfg.Database.URL); err != nil {
		return nil, func() {}, fmt.Errorf("running resource migrations: %w", err)
	}

	pool, err := postgres.Connect(context.Background(), cfg.Database.URL)
	if err != nil {
		return nil, func() {}, fmt.Errorf("connecting to database: %w", err)
	}

	logger.Info("using PostgreSQL resource repository")
	return postgres.NewResourceRepository(pool), pool.Close, nil
}
