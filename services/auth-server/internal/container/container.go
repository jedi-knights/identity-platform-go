package container

import (
	"fmt"
	"net/http"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/clientregistry"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/identityservice"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	policyadapter "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/policyservice"
	redisadapter "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Container holds all wired service dependencies.
type Container struct {
	Logger  logging.Logger
	Handler *inboundhttp.Handler
	Config  *config.Config
}

// New creates and wires all dependencies.
//
// Adapter selection:
//   - TokenRepository: Redis adapter when AUTH_REDIS_URL is set;
//     in-memory adapter otherwise (local dev / single-replica deployments).
//   - RefreshTokenRepository: Redis adapter when AUTH_REDIS_URL is set;
//     in-memory adapter otherwise (local dev / single-replica deployments).
//   - ClientAuthenticator: HTTP adapter (client-registry-service) when AUTH_CLIENT_REGISTRY_URL is set;
//     in-memory adapter otherwise (local dev / testing without the full stack).
//   - UserAuthenticator: HTTP adapter (identity-service) when AUTH_IDENTITY_SERVICE_URL is set;
//     nil otherwise (authorization_code grant remains a stub).
//   - SubjectPermissionsFetcher: HTTP adapter (authorization-policy-service) when AUTH_POLICY_URL is set;
//     nil otherwise (tokens are issued without roles/permissions claims).
func New(cfg *config.Config, logger logging.Logger) (*Container, error) {
	if cfg == nil {
		return nil, apperrors.New(apperrors.ErrCodeInternal, "config is required")
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}

	tokenRepo, refreshTokenRepo, err := buildTokenRepos(cfg, logger, httpClient)
	if err != nil {
		return nil, err
	}

	// buildClientAuth returns both the authenticator and the underlying repo so that
	// AuthorizationCodeStrategy (which needs direct repo access for redirect URI validation)
	// shares the same in-memory store — no duplicate seed, no split state.
	clientAuth, clientRepoForAC := buildClientAuth(cfg, logger, httpClient)
	userAuth := buildUserAuth(cfg, logger, httpClient)
	permsFetcher := buildPermsFetcher(cfg, logger)

	signingKey := []byte(cfg.JWT.SigningKey)
	tokenGen := application.NewJWTTokenGenerator(signingKey, cfg.JWT.Issuer, cfg.JWT.Audience)
	tokenVal := application.NewJWTTokenValidator(signingKey, tokenRepo)

	ttl := time.Duration(cfg.Token.TTLSeconds) * time.Second
	refreshTTL := time.Duration(cfg.Token.RefreshTokenTTLSeconds) * time.Second

	ccStrategy := application.NewClientCredentialsStrategy(clientAuth, tokenRepo, refreshTokenRepo, tokenGen, permsFetcher, ttl, refreshTTL)
	acStrategy := application.NewAuthorizationCodeStrategy(clientRepoForAC, tokenRepo, tokenGen, ttl, userAuth)
	rtStrategy := application.NewRefreshTokenStrategy(clientAuth, tokenRepo, refreshTokenRepo, tokenGen, permsFetcher, ttl, refreshTTL)
	grantRegistry := application.NewGrantStrategyRegistry(ccStrategy, acStrategy, rtStrategy)
	tokenSvc := application.NewTokenService(tokenRepo, refreshTokenRepo, tokenVal)

	issuer := inboundhttp.NewTokenIssuerAdapter(grantRegistry)
	introspector := inboundhttp.NewTokenIntrospectorAdapter(tokenSvc)
	revoker := inboundhttp.NewTokenRevokerAdapter(tokenSvc)
	handler := inboundhttp.NewHandler(issuer, introspector, revoker, clientAuth, logger, cfg.Introspection.Secret)

	return &Container{
		Logger:  logger,
		Handler: handler,
		Config:  cfg,
	}, nil
}

// buildTokenRepos selects the token and refresh-token repositories.
// Uses Redis when AUTH_REDIS_URL is set; falls back to in-memory for local dev.
// Warning: the in-memory store is not correct under multi-replica deployments —
// each replica holds an independent copy of its data (see ADR-0005).
func buildTokenRepos(cfg *config.Config, logger logging.Logger, httpClient *http.Client) (domain.TokenRepository, domain.RefreshTokenRepository, error) {
	_ = httpClient // reserved for future durable adapters that share the HTTP client
	if cfg.Redis.URL != "" {
		logger.Info("using Redis token store", "url", cfg.Redis.URL)
		redisClient, err := redisadapter.NewClient(cfg.Redis.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("connecting to Redis: %w", err)
		}
		return redisadapter.NewTokenRepository(redisClient), redisadapter.NewRefreshTokenRepository(redisClient), nil
	}
	logger.Info("using in-memory token store (AUTH_REDIS_URL not set); revoked tokens will not be rejected at scale")
	return memory.NewTokenRepository(), memory.NewRefreshTokenRepository(), nil
}

// buildClientAuth selects the client authenticator and returns the underlying
// domain.ClientRepository alongside it. The repo is nil when the remote HTTP
// adapter is selected — AuthorizationCodeStrategy receives nil and skips
// redirect-URI validation (the grant is a stub until PKCE is implemented).
//
// Returning the repo here avoids creating a second independent in-memory store:
// both the authenticator and the authorization-code strategy share the same instance.
func buildClientAuth(cfg *config.Config, logger logging.Logger, httpClient *http.Client) (ports.ClientAuthenticator, domain.ClientRepository) {
	if cfg.ClientRegistry.URL != "" {
		logger.Info("using remote client-registry-service", "url", cfg.ClientRegistry.URL)
		return clientregistry.NewClientAuthenticator(cfg.ClientRegistry.URL, httpClient), nil
	}
	logger.Info("using in-memory client store (AUTH_CLIENT_REGISTRY_URL not set)")
	var seedClients []*domain.Client
	if cfg.DevSeedClients {
		seedClients = devClients(cfg.DevClientSecret)
	}
	repo := memory.NewClientRepository(seedClients)
	return memory.NewClientAuthenticator(repo), repo
}

// buildUserAuth selects the user authenticator.
// Returns nil when AUTH_IDENTITY_SERVICE_URL is not set — the authorization_code
// grant remains a stub until the full PKCE flow is implemented.
func buildUserAuth(cfg *config.Config, logger logging.Logger, httpClient *http.Client) ports.UserAuthenticator {
	if cfg.IdentityService.URL != "" {
		logger.Info("using remote identity-service", "url", cfg.IdentityService.URL)
		return identityservice.NewUserAuthenticator(cfg.IdentityService.URL, httpClient)
	}
	return nil
}

// buildPermsFetcher selects the subject-permissions fetcher for RBAC claims.
// Returns nil when AUTH_POLICY_URL is not set — tokens are issued without
// roles/permissions claims; resource services fall back to scope-only authorization.
func buildPermsFetcher(cfg *config.Config, logger logging.Logger) ports.SubjectPermissionsFetcher {
	if cfg.Policy.URL != "" {
		logger.Info("using remote authorization-policy-service", "url", cfg.Policy.URL)
		return policyadapter.New(cfg.Policy.URL)
	}
	return nil
}

// devClients returns a seed client for local development only.
// The secret is loaded from AUTH_DEV_CLIENT_SECRET — never hardcode it.
// Never enable AUTH_DEV_SEED_CLIENTS in production.
func devClients(secret string) []*domain.Client {
	return []*domain.Client{
		{
			ID:         "dev-client",
			Secret:     secret,
			Name:       "Development Client",
			Scopes:     []string{"read", "write"},
			GrantTypes: []domain.GrantType{domain.GrantTypeClientCredentials},
		},
	}
}
