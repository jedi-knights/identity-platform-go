package container

import (
	"fmt"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Container holds all wired service dependencies.
type Container struct {
	Logger  logging.Logger
	Handler *inboundhttp.Handler
	Config  *config.Config
}

// New creates and wires all dependencies.
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Outbound adapters (repositories).
	tokenRepo := memory.NewTokenRepository()
	clientRepo := memory.NewClientRepository(defaultClients())

	// Token generator and validator.
	signingKey := []byte(cfg.JWT.SigningKey)
	tokenGen := application.NewJWTTokenGenerator(signingKey, cfg.JWT.Issuer)
	tokenVal := application.NewJWTTokenValidator(signingKey, tokenRepo)

	// Application layer.
	ttl := time.Duration(cfg.Token.TTLSeconds) * time.Second
	ccStrategy := application.NewClientCredentialsStrategy(clientRepo, tokenRepo, tokenGen, ttl)
	acStrategy := application.NewAuthorizationCodeStrategy(clientRepo, tokenRepo, tokenGen, ttl)
	grantRegistry := application.NewGrantStrategyRegistry(ccStrategy, acStrategy)
	tokenSvc := application.NewTokenService(tokenRepo, tokenVal)

	// Inbound adapters.
	issuer := inboundhttp.NewTokenIssuerAdapter(grantRegistry)
	introspector := inboundhttp.NewTokenIntrospectorAdapter(tokenSvc)
	revoker := inboundhttp.NewTokenRevokerAdapter(tokenSvc)
	handler := inboundhttp.NewHandler(issuer, introspector, revoker, logger)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
	}, nil
}

// defaultClients returns sample OAuth clients for development/testing.
func defaultClients() []*domain.Client {
	return []*domain.Client{
		{
			ID:         "test-client",
			Secret:     "test-secret",
			Name:       "Test Client",
			Scopes:     []string{"read", "write"},
			GrantTypes: []domain.GrantType{domain.GrantTypeClientCredentials},
		},
	}
}
