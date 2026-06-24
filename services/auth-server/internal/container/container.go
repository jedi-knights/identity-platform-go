// Package container wires the auth-server's dependencies through the
// platform DI container. Resolution from the returned container is
// restricted to the composition root in cmd/main.go and tests; business
// code receives its dependencies via constructor parameters.
package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	platform "github.com/jedi-knights/go-platform/container"

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

// New constructs and bootstraps a platform container wired with every
// dependency this service needs.
//
// Adapter selection (preserved verbatim from the prior implementation):
//   - TokenRepository / RefreshTokenRepository: Redis when AUTH_REDIS_URL
//     is set; in-memory otherwise. The Redis client is registered as an
//     OnClose hook so a graceful shutdown drains it.
//   - ClientAuthenticator: HTTP adapter (client-registry-service) when
//     AUTH_CLIENT_REGISTRY_URL is set; in-memory otherwise. When in-memory
//     is selected, AuthorizationCodeStrategy receives the same underlying
//     repo so there is no duplicate seed.
//   - UserAuthenticator: HTTP adapter (identity-service) when
//     AUTH_IDENTITY_SERVICE_URL is set; nil otherwise.
//   - SubjectPermissionsFetcher: HTTP adapter (authorization-policy-service)
//     when AUTH_POLICY_URL is set; nil otherwise.
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
	platform.Register(c, httpClientProvider)
	platform.Register(c, tokenRepositoriesProvider)
	platform.Register(c, clientWiringProvider)
	platform.Register(c, userAuthenticatorProvider)
	platform.Register(c, permissionsFetcherProvider)
	platform.Register(c, signingKeySetProvider)
	platform.Register(c, tokenGeneratorProvider)
	platform.Register(c, tokenValidatorProvider)
	platform.Register(c, clientCredentialsStrategyProvider)
	platform.Register(c, authorizationCodeStrategyProvider)
	platform.Register(c, refreshTokenStrategyProvider)
	platform.Register(c, grantRegistryProvider)
	platform.Register(c, tokenServiceProvider)
	platform.Register(c, handlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

func httpClientProvider(context.Context, *platform.Container) (*http.Client, error) {
	return &http.Client{Timeout: 5 * time.Second}, nil
}

// tokenRepositories bundles the two token-related repos so they share a
// single Redis client when AUTH_REDIS_URL is set, and a single OnClose hook
// drains that client at shutdown.
type tokenRepositories struct {
	token   domain.TokenRepository
	refresh domain.RefreshTokenRepository
}

func tokenRepositoriesProvider(ctx context.Context, c *platform.Container) (*tokenRepositories, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Redis.URL == "" {
		log.Info("using in-memory token store (AUTH_REDIS_URL not set); revoked tokens will not be rejected at scale")
		return &tokenRepositories{
			token:   memory.NewTokenRepository(),
			refresh: memory.NewRefreshTokenRepository(),
		}, nil
	}
	log.Info("using Redis token store", "url", cfg.Redis.URL)
	redisClient, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Redis: %w", err)
	}
	c.OnClose("redis", func(_ context.Context) error {
		return redisClient.Close()
	})
	return &tokenRepositories{
		token:   redisadapter.NewTokenRepository(redisClient),
		refresh: redisadapter.NewRefreshTokenRepository(redisClient),
	}, nil
}

// clientWiring bundles the ClientAuthenticator with the underlying
// domain.ClientRepository so AuthorizationCodeStrategy (which needs direct
// repo access for redirect URI validation) shares the same in-memory store
// as the authenticator — no duplicate seed, no split state. The repo is nil
// when the remote HTTP adapter is selected; AuthorizationCodeStrategy
// receives nil and skips redirect-URI validation (the grant is a stub
// until PKCE is implemented).
type clientWiring struct {
	authenticator ports.ClientAuthenticator
	repoForAC     domain.ClientRepository
}

func clientWiringProvider(ctx context.Context, c *platform.Container) (*clientWiring, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	if cfg.ClientRegistry.URL != "" {
		log.Info("using remote client-registry-service", "url", cfg.ClientRegistry.URL)
		return &clientWiring{
			authenticator: clientregistry.NewClientAuthenticator(cfg.ClientRegistry.URL, httpClient),
		}, nil
	}
	log.Info("using in-memory client store (AUTH_CLIENT_REGISTRY_URL not set)")
	var seedClients []*domain.Client
	if cfg.DevSeedClients {
		seedClients = devClients(cfg.DevClientSecret)
	}
	repo := memory.NewClientRepository(seedClients)
	return &clientWiring{
		authenticator: memory.NewClientAuthenticator(repo),
		repoForAC:     repo,
	}, nil
}

func userAuthenticatorProvider(ctx context.Context, c *platform.Container) (ports.UserAuthenticator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	if cfg.IdentityService.URL == "" {
		return nil, nil
	}
	log.Info("using remote identity-service", "url", cfg.IdentityService.URL)
	return identityservice.NewUserAuthenticator(cfg.IdentityService.URL, httpClient), nil
}

func permissionsFetcherProvider(ctx context.Context, c *platform.Container) (ports.SubjectPermissionsFetcher, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Policy.URL == "" {
		return nil, nil
	}
	log.Info("using remote authorization-policy-service", "url", cfg.Policy.URL)
	return policyadapter.New(cfg.Policy.URL), nil
}

// resolvedSigningAlg returns the configured signing alg, treating an empty
// value as the default (RS256). This lets direct callers of container.New —
// including tests that build a Config struct by hand — get the same default
// as config.Load() callers without setting the field explicitly.
func resolvedSigningAlg(cfg *config.Config) string {
	if cfg.JWT.SigningAlg == "" {
		return config.SigningAlgRS256
	}
	return cfg.JWT.SigningAlg
}

// signingKeySetProvider builds the RSA KeySet for RS256 mode. Loads the
// current key from AUTH_JWT_RSA_PRIVATE_KEY_PEM when set; generates a fresh
// in-memory 2048-bit keypair otherwise (the dev-friendly fallback per ADR-0008).
// In HS256 mode, returns nil — the resolver will not be called from the HS256
// generator/validator providers, but the registration must succeed.
func signingKeySetProvider(ctx context.Context, c *platform.Container) (*domain.KeySet, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if resolvedSigningAlg(cfg) != config.SigningAlgRS256 {
		return nil, nil
	}
	current, err := loadOrGenerateCurrentKey(cfg.JWT.RSAPrivateKeyPEM, log)
	if err != nil {
		return nil, fmt.Errorf("loading current signing key: %w", err)
	}
	retiring, err := loadOptionalKey("AUTH_JWT_RSA_PRIVATE_KEY_PEM_PREVIOUS", cfg.JWT.RSAPrivateKeyPEMPrevious, "retiring")
	if err != nil {
		return nil, err
	}
	next, err := loadOptionalKey("AUTH_JWT_RSA_PRIVATE_KEY_PEM_NEXT", cfg.JWT.RSAPrivateKeyPEMNext, "next")
	if err != nil {
		return nil, err
	}
	return domain.NewKeySet(current, retiring, next)
}

// loadOrGenerateCurrentKey returns the current signing key. PEM env var wins
// when set; otherwise a fresh in-memory keypair is generated with a kid
// derived from a CSPRNG hex string — distinct across restarts so consumers
// will see the kid change and refresh their JWKS cache.
func loadOrGenerateCurrentKey(pemStr string, log logging.Logger) (*domain.SigningKey, error) {
	if pemStr != "" {
		log.Info("loading RSA signing key from AUTH_JWT_RSA_PRIVATE_KEY_PEM")
		return domain.LoadSigningKey(pemStr, "current")
	}
	kid, err := randomKID("dev-")
	if err != nil {
		return nil, fmt.Errorf("generating kid: %w", err)
	}
	log.Info("AUTH_JWT_RSA_PRIVATE_KEY_PEM not set; generating in-memory RSA keypair (tokens will not survive restart)", "kid", kid)
	return domain.GenerateSigningKey(kid)
}

func loadOptionalKey(envName, pemStr, slot string) (*domain.SigningKey, error) {
	if pemStr == "" {
		return nil, nil
	}
	key, err := domain.LoadSigningKey(pemStr, slot)
	if err != nil {
		return nil, fmt.Errorf("loading %s signing key from %s: %w", slot, envName, err)
	}
	return key, nil
}

// randomKID returns prefix + 16 hex chars of CSPRNG entropy. 64 bits of entropy
// is plenty for a non-secret identifier whose only job is to disambiguate
// concurrently-live signing keys.
func randomKID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func tokenGeneratorProvider(ctx context.Context, c *platform.Container) (application.TokenGenerator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if resolvedSigningAlg(cfg) == config.SigningAlgRS256 {
		keys := platform.MustResolve[*domain.KeySet](ctx, c)
		return application.NewRS256TokenGenerator(keys, cfg.JWT.Issuer, cfg.JWT.Audience), nil
	}
	return application.NewJWTTokenGenerator([]byte(cfg.JWT.SigningKey), cfg.JWT.Issuer, cfg.JWT.Audience), nil
}

func tokenValidatorProvider(ctx context.Context, c *platform.Container) (application.TokenValidator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	if resolvedSigningAlg(cfg) == config.SigningAlgRS256 {
		keys := platform.MustResolve[*domain.KeySet](ctx, c)
		return application.NewRS256TokenValidator(keys, repos.token, cfg.JWT.Issuer), nil
	}
	return application.NewJWTTokenValidator([]byte(cfg.JWT.SigningKey), repos.token, cfg.JWT.Issuer), nil
}

func clientCredentialsStrategyProvider(ctx context.Context, c *platform.Container) (*application.ClientCredentialsStrategy, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	gen := platform.MustResolve[application.TokenGenerator](ctx, c)
	fetcher := platform.MustResolve[ports.SubjectPermissionsFetcher](ctx, c)
	ttl, refreshTTL := tokenTTLs(cfg)
	return application.NewClientCredentialsStrategy(cw.authenticator, repos.token, repos.refresh, gen, fetcher, ttl, refreshTTL), nil
}

func authorizationCodeStrategyProvider(ctx context.Context, c *platform.Container) (*application.AuthorizationCodeStrategy, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	gen := platform.MustResolve[application.TokenGenerator](ctx, c)
	userAuth := platform.MustResolve[ports.UserAuthenticator](ctx, c)
	ttl, _ := tokenTTLs(cfg)
	return application.NewAuthorizationCodeStrategy(cw.repoForAC, repos.token, gen, ttl, userAuth), nil
}

func refreshTokenStrategyProvider(ctx context.Context, c *platform.Container) (*application.RefreshTokenStrategy, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	gen := platform.MustResolve[application.TokenGenerator](ctx, c)
	fetcher := platform.MustResolve[ports.SubjectPermissionsFetcher](ctx, c)
	ttl, refreshTTL := tokenTTLs(cfg)
	return application.NewRefreshTokenStrategy(cw.authenticator, repos.token, repos.refresh, gen, fetcher, ttl, refreshTTL), nil
}

func grantRegistryProvider(ctx context.Context, c *platform.Container) (*application.GrantStrategyRegistry, error) {
	cc := platform.MustResolve[*application.ClientCredentialsStrategy](ctx, c)
	ac := platform.MustResolve[*application.AuthorizationCodeStrategy](ctx, c)
	rt := platform.MustResolve[*application.RefreshTokenStrategy](ctx, c)
	return application.NewGrantStrategyRegistry(cc, ac, rt), nil
}

func tokenServiceProvider(ctx context.Context, c *platform.Container) (*application.TokenService, error) {
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	val := platform.MustResolve[application.TokenValidator](ctx, c)
	return application.NewTokenService(repos.token, repos.refresh, val), nil
}

func handlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.Handler, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	grants := platform.MustResolve[*application.GrantStrategyRegistry](ctx, c)
	tokens := platform.MustResolve[*application.TokenService](ctx, c)

	issuer := inboundhttp.NewTokenIssuerAdapter(grants)
	introspector := inboundhttp.NewTokenIntrospectorAdapter(tokens)
	revoker := inboundhttp.NewTokenRevokerAdapter(tokens)
	return inboundhttp.NewHandler(issuer, introspector, revoker, cw.authenticator, log, cfg.Introspection.Secret), nil
}

func tokenTTLs(cfg *config.Config) (time.Duration, time.Duration) {
	return time.Duration(cfg.Token.TTLSeconds) * time.Second,
		time.Duration(cfg.Token.RefreshTokenTTLSeconds) * time.Second
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
