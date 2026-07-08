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
	"strings"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"
	platform "github.com/jedi-knights/go-platform/container"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/clientregistry"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/identityservice"
	jwksadapter "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/jwks"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	policyadapter "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/policyservice"
	redisadapter "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/redis"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/observability"
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
	platform.Register(c, auditEmitterProvider)
	platform.Register(c, tokenRepositoriesProvider)
	platform.Register(c, authorizationCodeRepositoryProvider)
	platform.Register(c, authorizationCodeIssuerProvider)
	platform.Register(c, loginChallengeRepositoryProvider)
	platform.Register(c, pushedAuthorizationRequestRepositoryProvider)
	platform.Register(c, deviceAuthorizationRepositoryProvider)
	platform.Register(c, clientAssertionReplayRepositoryProvider)
	platform.Register(c, clientJWKSFetcherProvider)
	platform.Register(c, dpopProofRepositoryProvider)
	platform.Register(c, dpopValidatorProvider)
	platform.Register(c, clientWiringProvider)
	platform.Register(c, userAuthenticatorProvider)
	platform.Register(c, userClaimsFetcherProvider)
	platform.Register(c, idTokenGeneratorProvider)
	platform.Register(c, permissionsFetcherProvider)
	platform.Register(c, signingKeySetProvider)
	platform.Register(c, tokenGeneratorProvider)
	platform.Register(c, tokenValidatorProvider)
	platform.Register(c, clientAssertionValidatorProvider)
	platform.Register(c, clientCredentialsStrategyProvider)
	platform.Register(c, authorizationCodeStrategyProvider)
	platform.Register(c, refreshTokenStrategyProvider)
	platform.Register(c, tokenExchangeStrategyProvider)
	platform.Register(c, deviceCodeStrategyProvider)
	platform.Register(c, samlBearerStrategyProvider)
	platform.Register(c, grantRegistryProvider)
	platform.Register(c, tokenServiceProvider)
	platform.Register(c, handlerProvider)
	platform.Register(c, jwksHandlerProvider)
	platform.Register(c, deviceAuthorizationHandlerProvider)
	platform.Register(c, userInfoHandlerProvider)
	platform.Register(c, metadataBuilderProvider)
	platform.Register(c, metadataHandlerProvider)

	if err := c.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping container: %w", err)
	}
	return c, nil
}

func httpClientProvider(context.Context, *platform.Container) (*http.Client, error) {
	// otelhttp.NewTransport wraps the default transport so every
	// outbound request becomes a client span and carries the W3C
	// traceparent header. The wrapper is inert when tracing is
	// disabled — no spans are emitted but the header propagation still
	// runs, which is the correct behaviour for a no-op TracerProvider.
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}, nil
}

// auditEmitterProvider builds the audit.Emitter per ADR-0018 + ADR-0019.
// When AUTH_AUDIT_DURABLE_DSN is set the emitter writes through a Postgres
// durable sink in addition to the best-effort stderr sink, and the
// returned pool is registered as an OnClose hook for graceful shutdown.
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
// domain.ClientRepository so the authentication path can share the same
// in-memory store as the seeded test client when running without a remote
// client registry. The repo is nil when the remote HTTP adapter is selected;
// the authorization_code grant authenticates via ClientAuthenticator only.
type clientWiring struct {
	authenticator ports.ClientAuthenticator
	repoForAC     domain.ClientRepository // unused by AuthorizationCodeStrategy after ADR-0009
}

// authorizationCodeRepositoryProvider wires the auth-code store. Uses the
// Redis adapter when AUTH_REDIS_URL is set (atomic Lua-script Consume),
// otherwise the in-memory adapter (mutex-protected, single-replica).
func authorizationCodeRepositoryProvider(ctx context.Context, c *platform.Container) (domain.AuthorizationCodeRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Redis.URL == "" {
		log.Info("using in-memory authorization-code store (AUTH_REDIS_URL not set)")
		return memory.NewAuthorizationCodeRepository(), nil
	}
	log.Info("using Redis authorization-code store")
	client, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Redis for auth codes: %w", err)
	}
	return redisadapter.NewAuthorizationCodeRepository(client), nil
}

// loginChallengeRepositoryProvider wires the LoginChallenge store. Mirrors
// the authorization-code repository: Redis when AUTH_REDIS_URL is set, the
// in-memory adapter otherwise. ADR-0011.
func loginChallengeRepositoryProvider(ctx context.Context, c *platform.Container) (domain.LoginChallengeRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Redis.URL == "" {
		log.Info("using in-memory login-challenge store (AUTH_REDIS_URL not set)")
		return memory.NewLoginChallengeRepository(), nil
	}
	log.Info("using Redis login-challenge store")
	client, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Redis for login challenges: %w", err)
	}
	return redisadapter.NewLoginChallengeRepository(client), nil
}

// pushedAuthorizationRequestRepositoryProvider wires the PAR store (RFC
// 9126, ADR-0021). Mirrors authorizationCodeRepositoryProvider exactly:
// Redis when AUTH_REDIS_URL is set, the in-memory adapter otherwise.
func pushedAuthorizationRequestRepositoryProvider(ctx context.Context, c *platform.Container) (domain.PushedAuthorizationRequestRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Redis.URL == "" {
		log.Info("using in-memory pushed-authorization-request store (AUTH_REDIS_URL not set)")
		return memory.NewPushedAuthorizationRequestRepository(), nil
	}
	log.Info("using Redis pushed-authorization-request store")
	client, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Redis for pushed authorization requests: %w", err)
	}
	return redisadapter.NewPushedAuthorizationRequestRepository(client), nil
}

// deviceAuthorizationRepositoryProvider wires the RFC 8628 device
// authorization store. Mirrors the authorization-code and login-challenge
// repositories: Redis when AUTH_REDIS_URL is set, the in-memory adapter
// otherwise. ADR-0022.
func deviceAuthorizationRepositoryProvider(ctx context.Context, c *platform.Container) (domain.DeviceAuthorizationRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Redis.URL == "" {
		log.Info("using in-memory device-authorization store (AUTH_REDIS_URL not set)")
		return memory.NewDeviceAuthorizationRepository(), nil
	}
	log.Info("using Redis device-authorization store")
	client, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Redis for device authorizations: %w", err)
	}
	return redisadapter.NewDeviceAuthorizationRepository(client), nil
}

// clientAssertionReplayRepositoryProvider wires the RFC 7523 client-
// assertion jti replay-protection store (ADR-0023). Mirrors every other
// repository in this container: Redis when AUTH_REDIS_URL is set, the
// in-memory adapter otherwise.
func clientAssertionReplayRepositoryProvider(ctx context.Context, c *platform.Container) (domain.ClientAssertionReplayRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Redis.URL == "" {
		log.Info("using in-memory client-assertion replay store (AUTH_REDIS_URL not set)")
		return memory.NewClientAssertionReplayRepository(), nil
	}
	log.Info("using Redis client-assertion replay store")
	client, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Redis for client-assertion replay: %w", err)
	}
	return redisadapter.NewClientAssertionReplayRepository(client), nil
}

// clientJWKSFetcherProvider wires the per-client JWKS fetcher RFC 7523
// client-assertion verification uses to resolve each client's own
// registered signing key (ADR-0023) — distinct from this platform's own
// single-URL JWKS fetchers in example-resource-service /
// token-introspection-service, which verify tokens *this* platform
// issued rather than third-party client assertions.
func clientJWKSFetcherProvider(ctx context.Context, c *platform.Container) (ports.ClientJWKSFetcher, error) {
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	return jwksadapter.NewPerClientFetcher(httpClient), nil
}

// clientAssertionValidatorProvider wires the RFC 7523 JWT-bearer client-
// assertion validator (ADR-0023) shared by every grant strategy that
// supports it. Resolves nil when the wired ClientAuthenticator does not
// also implement ports.ClientLookup — in practice this never happens
// today (both the memory and clientregistry adapters implement both),
// but mirrors authorizeConfigFor's existing defensive type-assertion
// pattern rather than assuming the interface pairing holds forever.
func clientAssertionValidatorProvider(ctx context.Context, c *platform.Container) (*application.ClientAssertionValidator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	lookup, ok := cw.authenticator.(ports.ClientLookup)
	if !ok {
		return nil, nil //nolint:nilnil // documented degradation path
	}
	fetcher := platform.MustResolve[ports.ClientJWKSFetcher](ctx, c)
	replayRepo := platform.MustResolve[domain.ClientAssertionReplayRepository](ctx, c)
	return application.NewClientAssertionValidator(lookup, fetcher, replayRepo, cfg.JWT.Issuer), nil
}

// dpopProofRepositoryProvider wires the DPoP proof jti replay cache
// (ADR-0025). Mirrors the authorization-code repository: Redis when
// AUTH_REDIS_URL is set, the in-memory adapter otherwise.
func dpopProofRepositoryProvider(ctx context.Context, c *platform.Container) (domain.DPoPProofRepository, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	if cfg.Redis.URL == "" {
		log.Info("using in-memory dpop proof replay cache (AUTH_REDIS_URL not set)")
		return memory.NewDPoPProofRepository(), nil
	}
	log.Info("using Redis dpop proof replay cache")
	client, err := redisadapter.NewClient(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Redis for dpop proofs: %w", err)
	}
	return redisadapter.NewDPoPProofRepository(client), nil
}

// dpopValidatorProvider wires application.DPoPValidator (ADR-0025). Always
// available — DPoP has no external dependency, so unlike the outbound
// service ports there is no nil-fallback branch here; a client simply opts
// in per request by sending a DPoP header or not.
func dpopValidatorProvider(ctx context.Context, c *platform.Container) (*application.DPoPValidator, error) {
	repo := platform.MustResolve[domain.DPoPProofRepository](ctx, c)
	return application.NewDPoPValidator(repo), nil
}

// authorizationCodeIssuerProvider wires the application-layer issuer that
// ADR-0011's /oauth/authorize handler will call once user identity and
// consent are established. Bound via the ports.AuthorizationCodeIssuer
// interface so the handler can be tested without a real container.
func authorizationCodeIssuerProvider(ctx context.Context, c *platform.Container) (ports.AuthorizationCodeIssuer, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	repo := platform.MustResolve[domain.AuthorizationCodeRepository](ctx, c)
	ttl := time.Duration(cfg.AuthorizationCode.TTLSeconds) * time.Second
	return application.NewAuthorizationCodeIssuer(repo, ttl), nil
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

// userClaimsFetcherProvider wires the OIDC claim-projection adapter
// (ADR-0010). Nil when AUTH_IDENTITY_SERVICE_URL is unset — the ID-token
// issuer then omits profile/email claims and /userinfo returns 503.
func userClaimsFetcherProvider(ctx context.Context, c *platform.Container) (ports.UserClaimsFetcher, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	httpClient := platform.MustResolve[*http.Client](ctx, c)
	if cfg.IdentityService.URL == "" {
		return nil, nil
	}
	return identityservice.NewUserClaimsFetcher(cfg.IdentityService.URL, httpClient), nil
}

// idTokenGeneratorProvider wires the OIDC ID-token generator. Nil when
// AUTH_JWT_OIDC_ISSUER is empty or the signing alg is HS256 — the
// authorization_code strategy then keeps the OAuth-only response shape.
func idTokenGeneratorProvider(ctx context.Context, c *platform.Container) (*application.IDTokenGenerator, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.JWT.OIDCIssuer == "" {
		return nil, nil
	}
	if resolvedSigningAlg(cfg) != config.SigningAlgRS256 {
		return nil, nil
	}
	keys := platform.MustResolve[*domain.KeySet](ctx, c)
	return application.NewIDTokenGenerator(keys, cfg.JWT.OIDCIssuer), nil
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
	assertionAuth := platform.MustResolve[*application.ClientAssertionValidator](ctx, c)
	ttl, refreshTTL := tokenTTLs(cfg)
	return application.NewClientCredentialsStrategy(cw.authenticator, repos.token, repos.refresh, gen, fetcher, ttl, refreshTTL, assertionAuth), nil
}

func authorizationCodeStrategyProvider(ctx context.Context, c *platform.Container) (*application.AuthorizationCodeStrategy, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	codeRepo := platform.MustResolve[domain.AuthorizationCodeRepository](ctx, c)
	gen := platform.MustResolve[application.TokenGenerator](ctx, c)
	fetcher := platform.MustResolve[ports.SubjectPermissionsFetcher](ctx, c)
	ttl, refreshTTL := tokenTTLs(cfg)
	// claimsFetcher + idTokenGen are nil-resolved when AUTH_IDENTITY_SERVICE_URL
	// is unset or the signing alg is HS256 — the strategy then skips OIDC
	// issuance regardless of the openid scope, matching the legacy OAuth shape.
	claimsFetcher, _ := platform.Resolve[ports.UserClaimsFetcher](ctx, c)
	idTokenGen, _ := platform.Resolve[*application.IDTokenGenerator](ctx, c)
	assertionAuth := platform.MustResolve[*application.ClientAssertionValidator](ctx, c)
	idTokenTTL := time.Duration(cfg.JWT.IDTokenTTLSeconds) * time.Second
	return application.NewAuthorizationCodeStrategy(cw.authenticator, codeRepo, repos.token, repos.refresh, gen, fetcher, claimsFetcher, idTokenGen, ttl, refreshTTL, idTokenTTL, assertionAuth), nil
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
	assertionAuth := platform.MustResolve[*application.ClientAssertionValidator](ctx, c)
	ttl, refreshTTL := tokenTTLs(cfg)
	return application.NewRefreshTokenStrategy(cw.authenticator, repos.token, repos.refresh, gen, fetcher, ttl, refreshTTL, assertionAuth), nil
}

// tokenExchangeStrategyProvider wires the RFC 8693 token-exchange
// grant strategy (ADR-0016). The strategy validates a presented
// subject_token using the same TokenValidator the introspection path
// uses, so a token revoked via ADR-0014's refresh-token cascade is
// already unmintable here without any token-exchange-specific work.
func tokenExchangeStrategyProvider(ctx context.Context, c *platform.Container) (*application.TokenExchangeStrategy, error) {
	cw, err := platform.Resolve[*clientWiring](ctx, c)
	if err != nil {
		return nil, err
	}
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	validator := platform.MustResolve[application.TokenValidator](ctx, c)
	gen := platform.MustResolve[application.TokenGenerator](ctx, c)
	return application.NewTokenExchangeStrategy(application.TokenExchangeStrategyConfig{
		ClientAuth:     cw.authenticator,
		TokenValidator: validator,
		TokenRepo:      repos.token,
		TokenGen:       gen,
	}), nil
}

// deviceCodeStrategyProvider wires the RFC 8628 device_code grant strategy
// (ADR-0022). Shares the same token/refresh-token repos and TTLs as
// client_credentials; the device authorization store is its own repo
// since polling and consumption follow a different lifecycle than any
// existing grant.
func deviceCodeStrategyProvider(ctx context.Context, c *platform.Container) (*application.DeviceCodeStrategy, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	deviceAuthRepo := platform.MustResolve[domain.DeviceAuthorizationRepository](ctx, c)
	gen := platform.MustResolve[application.TokenGenerator](ctx, c)
	fetcher := platform.MustResolve[ports.SubjectPermissionsFetcher](ctx, c)
	ttl, refreshTTL := tokenTTLs(cfg)
	return application.NewDeviceCodeStrategy(cw.authenticator, deviceAuthRepo, repos.token, repos.refresh, gen, fetcher, ttl, refreshTTL), nil
}

// samlBearerStrategyProvider wires the RFC 7522 grant (ADR-0026).
// tokenEndpointURL is a static configured value, unlike DPoP's htu (checked
// against the live *http.Request inside Handler.Token) — grant strategies
// are called via ports.TokenIssuer.IssueToken(ctx, req) with no request in
// hand, so the expected audience/recipient must be known at wiring time.
// Empty AUTH_METADATA_PUBLIC_BASE_URL means no assertion can ever match
// (self-documenting: the grant is inert, not broken) rather than a
// container-startup failure.
func samlBearerStrategyProvider(ctx context.Context, c *platform.Container) (*application.SAMLBearerStrategy, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	cw := platform.MustResolve[*clientWiring](ctx, c)
	repos, err := platform.Resolve[*tokenRepositories](ctx, c)
	if err != nil {
		return nil, err
	}
	gen := platform.MustResolve[application.TokenGenerator](ctx, c)
	ttl, _ := tokenTTLs(cfg)
	tokenEndpointURL := strings.TrimRight(cfg.Metadata.PublicBaseURL, "/") + "/oauth/token"
	return application.NewSAMLBearerStrategy(
		cw.authenticator, repos.token, repos.refresh, gen,
		application.NewSAMLBearerValidator(), tokenEndpointURL, ttl,
	), nil
}

func grantRegistryProvider(ctx context.Context, c *platform.Container) (*application.GrantStrategyRegistry, error) {
	cc := platform.MustResolve[*application.ClientCredentialsStrategy](ctx, c)
	ac := platform.MustResolve[*application.AuthorizationCodeStrategy](ctx, c)
	rt := platform.MustResolve[*application.RefreshTokenStrategy](ctx, c)
	te := platform.MustResolve[*application.TokenExchangeStrategy](ctx, c)
	dc := platform.MustResolve[*application.DeviceCodeStrategy](ctx, c)
	sb := platform.MustResolve[*application.SAMLBearerStrategy](ctx, c)
	emitter := platform.MustResolve[audit.Emitter](ctx, c)
	return application.NewGrantStrategyRegistry(cc, ac, rt, te, dc, sb).WithAudit(emitter, "auth-server"), nil
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
	challengeRepo := platform.MustResolve[domain.LoginChallengeRepository](ctx, c)
	codeIssuer := platform.MustResolve[ports.AuthorizationCodeIssuer](ctx, c)
	parRepo := platform.MustResolve[domain.PushedAuthorizationRequestRepository](ctx, c)

	issuer := inboundhttp.NewTokenIssuerAdapter(grants)
	introspector := inboundhttp.NewTokenIntrospectorAdapter(tokens)
	revoker := inboundhttp.NewTokenRevokerAdapter(tokens)
	authorizeCfg := authorizeConfigFor(cfg, cw, challengeRepo, codeIssuer, parRepo)
	dpopValidator := platform.MustResolve[*application.DPoPValidator](ctx, c)
	emitter := platform.MustResolve[audit.Emitter](ctx, c)
	return inboundhttp.NewHandler(issuer, introspector, revoker, cw.authenticator, log, cfg.Introspection.Secret, authorizeCfg, dpopValidator).
		WithAudit(emitter, "auth-server"), nil
}

// authorizeConfigFor returns the AuthorizeConfig for /oauth/authorize +
// /internal/issue-code when LoginUI.URL is set, or nil — which makes the
// handlers fall back to their stubs. Both adapters (memory + clientregistry)
// satisfy ports.ClientLookup, so the authenticator is reused as the lookup
// port. ServiceToken is passed through verbatim; the handler refuses to
// serve /internal/issue-code when it is empty.
func authorizeConfigFor(
	cfg *config.Config,
	cw *clientWiring,
	repo domain.LoginChallengeRepository,
	codeIssuer ports.AuthorizationCodeIssuer,
	parRepo domain.PushedAuthorizationRequestRepository,
) *inboundhttp.AuthorizeConfig {
	if cfg.LoginUI.URL == "" {
		return nil
	}
	lookup, ok := cw.authenticator.(ports.ClientLookup)
	if !ok {
		return nil
	}
	return &inboundhttp.AuthorizeConfig{
		ClientLookup:    lookup,
		ChallengeRepo:   repo,
		LoginUIURL:      strings.TrimRight(cfg.LoginUI.URL, "/"),
		ChallengeTTL:    time.Duration(cfg.LoginChallenge.TTLSeconds) * time.Second,
		AuthCodeIssuer:  codeIssuer,
		IssueCodeBearer: cfg.LoginUI.ServiceToken,
		Issuer:          cfg.JWT.Issuer,
		PARRepo:         parRepo,
		PARTTL:          time.Duration(cfg.PAR.TTLSeconds) * time.Second,
	}
}

// deviceAuthorizationHandlerProvider wires the RFC 8628 device_authorization
// endpoint handler (ADR-0022). Nil when LoginUI.URL is unset — without a
// login-ui base URL there is no verification page to advertise, so the
// endpoint stays disabled, mirroring /oauth/authorize's own 501 stub
// behaviour under the same condition.
func deviceAuthorizationHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.DeviceAuthorizationHandler, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.LoginUI.URL == "" {
		return nil, nil
	}
	cw := platform.MustResolve[*clientWiring](ctx, c)
	repo := platform.MustResolve[domain.DeviceAuthorizationRepository](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	verificationURI := strings.TrimRight(cfg.LoginUI.URL, "/") + "/device"
	ttl := time.Duration(cfg.DeviceAuthorization.TTLSeconds) * time.Second
	return inboundhttp.NewDeviceAuthorizationHandler(cw.authenticator, repo, verificationURI, ttl, cfg.DeviceAuthorization.PollIntervalSeconds, cfg.LoginUI.ServiceToken, log), nil
}

// userInfoHandlerProvider wires the OIDC /userinfo handler. Nil when OIDC
// mode is disabled (no IDTokenGenerator → no issuer URL → no point serving
// /userinfo). The router skips registering the route in that case.
func userInfoHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.UserInfoHandler, error) {
	idTokenGen, _ := platform.Resolve[*application.IDTokenGenerator](ctx, c)
	if idTokenGen == nil {
		return nil, nil
	}
	validator := platform.MustResolve[application.TokenValidator](ctx, c)
	claimsFetcher, _ := platform.Resolve[ports.UserClaimsFetcher](ctx, c)
	log := platform.MustResolve[logging.Logger](ctx, c)
	return inboundhttp.NewUserInfoHandler(validator, claimsFetcher, log), nil
}

// jwksHandlerProvider builds the JWKS endpoint handler. Returns nil in HS256
// mode — the router uses nil-resolution to skip registering the route, since
// HS256 has nothing to publish as a JWKS document.
func jwksHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.JWKSHandler, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if resolvedSigningAlg(cfg) != config.SigningAlgRS256 {
		return nil, nil
	}
	keys := platform.MustResolve[*domain.KeySet](ctx, c)
	return inboundhttp.NewJWKSHandler(keys), nil
}

// metadataBuilderProvider constructs the RFC 8414 / OIDC Discovery 1.0
// metadata builder (ADR-0012). The builder is a pure function of running
// config — composed from the same wiring signals used by the routes
// (signing alg → JWKS, identity-service URL → /userinfo, login-ui URL →
// authorization_code grant). Returns nil when no public base URL is
// configured; the handler provider treats nil as "metadata disabled".
func metadataBuilderProvider(ctx context.Context, c *platform.Container) (*application.MetadataBuilder, error) {
	cfg := platform.MustResolve[*config.Config](ctx, c)
	if cfg.Metadata.PublicBaseURL == "" {
		return nil, nil
	}
	signingAlg := resolvedSigningAlg(cfg)
	endSession := ""
	if cfg.LoginUI.URL != "" {
		endSession = strings.TrimRight(cfg.LoginUI.URL, "/") + "/sign-out"
	}
	return application.NewMetadataBuilder(application.MetadataBuilderConfig{
		PublicBaseURL:        cfg.Metadata.PublicBaseURL,
		Issuer:               cfg.JWT.Issuer,
		OIDCIssuer:           cfg.JWT.OIDCIssuer,
		SigningAlg:           signingAlg,
		HasJWKS:              signingAlg == config.SigningAlgRS256,
		HasUserInfo:          cfg.JWT.OIDCIssuer != "" && cfg.IdentityService.URL != "",
		HasLoginUI:           cfg.LoginUI.URL != "",
		RegistrationEndpoint: cfg.Metadata.RegistrationEndpoint,
		ServiceDocumentation: cfg.Metadata.ServiceDocumentation,
		EndSessionEndpoint:   endSession,
	}), nil
}

// metadataHandlerProvider wires the RFC 8414 / OIDC Discovery handler.
// Returns nil when [metadataBuilderProvider] returned nil — the router
// uses nil-resolution to skip registering the well-known endpoints.
func metadataHandlerProvider(ctx context.Context, c *platform.Container) (*inboundhttp.MetadataHandler, error) {
	builder, _ := platform.Resolve[*application.MetadataBuilder](ctx, c)
	if builder == nil {
		return nil, nil
	}
	return inboundhttp.NewMetadataHandler(builder), nil
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
