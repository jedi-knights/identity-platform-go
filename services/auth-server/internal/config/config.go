package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all auth-server configuration.
type Config struct {
	Server              ServerConfig                     `mapstructure:"server"`
	JWT                 JWTConfig                        `mapstructure:"jwt"`
	Token               TokenConfig                      `mapstructure:"token"`
	AuthorizationCode   AuthorizationCodeConfig          `mapstructure:"authorization_code"`
	LoginChallenge      LoginChallengeConfig             `mapstructure:"login_challenge"`
	PAR                 PushedAuthorizationRequestConfig `mapstructure:"pushed_authorization_request"`
	DeviceAuthorization DeviceAuthorizationConfig        `mapstructure:"device_authorization"`
	Log                 LogConfig                        `mapstructure:"log"`
	ClientRegistry      ClientRegistryConfig             `mapstructure:"client_registry"`
	IdentityService     IdentityServiceConfig            `mapstructure:"identity_service"`
	Redis               RedisConfig                      `mapstructure:"redis"`
	Policy              PolicyConfig                     `mapstructure:"policy"`
	Introspection       IntrospectionConfig              `mapstructure:"introspection"`
	LoginUI             LoginUIConfig                    `mapstructure:"login_ui"`
	Audit               AuditConfig                      `mapstructure:"audit"`
	Metadata            MetadataConfig                   `mapstructure:"metadata"`
	Tracing             TracingConfig                    `mapstructure:"tracing"`
	DevSeedClients      bool                             `mapstructure:"dev_seed_clients"`
	DevClientSecret     string                           `mapstructure:"dev_client_secret"` // AUTH_DEV_CLIENT_SECRET; only used when DevSeedClients=true
}

// TracingConfig configures the OpenTelemetry SDK bootstrap (ADR-0014 /
// portfolio observability roadmap). Every field is optional; missing
// values fall back to OTEL_* environment variables and ultimately to a
// stdout exporter so traces are visible during local development without
// a collector.
//
// Enabled controls whether the SDK is bootstrapped at all. When false
// the global TracerProvider stays as the no-op default and outbound
// otelhttp wrappers emit no spans.
type TracingConfig struct {
	// Enabled toggles OTel bootstrap. Sourced from AUTH_TRACING_ENABLED.
	// Default false — opt-in until every dependent service ships the
	// same bootstrap and a collector is available.
	Enabled bool `mapstructure:"enabled"`

	// ServiceVersion is reported as the service.version resource
	// attribute. Sourced from AUTH_TRACING_SERVICE_VERSION; when empty
	// OTEL_SERVICE_VERSION is consulted.
	ServiceVersion string `mapstructure:"service_version"`

	// ExporterEndpoint overrides the OTLP endpoint. Empty defers to
	// OTEL_EXPORTER_OTLP_ENDPOINT; when that is also empty the SDK
	// falls back to a stdout exporter.
	ExporterEndpoint string `mapstructure:"exporter_endpoint"`

	// ExporterProtocol selects the OTLP transport ("grpc" or "http").
	// Empty defers to OTEL_EXPORTER_OTLP_PROTOCOL; default grpc.
	ExporterProtocol string `mapstructure:"exporter_protocol"`

	// ExporterInsecure disables TLS on the OTLP gRPC endpoint.
	ExporterInsecure bool `mapstructure:"exporter_insecure"`

	// SamplerRatio sets the head-based sampler ratio. Zero falls back
	// to 1 (sample every root span) inside the SDK; 0.1 keeps 10% of
	// traces.
	SamplerRatio float64 `mapstructure:"sampler_ratio"`
}

// MetadataConfig configures the RFC 8414 / OIDC Discovery 1.0 metadata
// endpoints (ADR-0012). PublicBaseURL is the absolute origin the
// auth-server is reachable at from clients — typically the
// gateway-fronted URL — used to construct authorization, token,
// introspection, revocation, JWKS, and userinfo URLs in the metadata
// document.
//
// When PublicBaseURL is empty the metadata endpoints are not registered.
// The JWKS endpoint continues to work because it does not need a
// configured base URL.
type MetadataConfig struct {
	// PublicBaseURL is the absolute origin the auth-server is reachable
	// at from clients. Defaults to "" — metadata endpoints disabled when
	// unset. Sourced from AUTH_METADATA_PUBLIC_BASE_URL.
	PublicBaseURL string `mapstructure:"public_base_url"`

	// ServiceDocumentation is an optional URL surfaced in the metadata
	// document so clients can discover human-readable docs.
	ServiceDocumentation string `mapstructure:"service_documentation"`

	// RegistrationEndpoint advertises the RFC 7591 dynamic-client-
	// registration URL. Empty omits the field — set this once ADR-0013
	// implementation lands in client-registry-service.
	RegistrationEndpoint string `mapstructure:"registration_endpoint"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type JWTConfig struct {
	// SigningAlg selects the JWT signing scheme. "RS256" (default) uses an
	// asymmetric RSA keypair so resource servers can verify tokens via JWKS
	// without holding forgery-equivalent secrets. "HS256" is the legacy
	// shared-HMAC path retained for backwards compatibility during migration.
	SigningAlg string `mapstructure:"signing_alg"` // AUTH_JWT_SIGNING_ALG

	// SigningKey is the HMAC secret used only when SigningAlg == "HS256".
	// Ignored under RS256.
	SigningKey string `mapstructure:"signing_key"` // AUTH_JWT_SIGNING_KEY

	// RSAPrivateKeyPEM is the PEM-encoded RSA private key used only when
	// SigningAlg == "RS256". When empty (and SigningAlg == "RS256"), the
	// service generates a fresh 2048-bit keypair in memory at startup —
	// suitable for local development; not durable across restarts.
	RSAPrivateKeyPEM string `mapstructure:"rsa_private_key_pem"` // AUTH_JWT_RSA_PRIVATE_KEY_PEM

	// RSAPrivateKeyPEMNext is an optional pre-staged successor key. When set,
	// its public half is included in JWKS so verifiers can pre-fetch it
	// before it becomes Current at the next rotation.
	RSAPrivateKeyPEMNext string `mapstructure:"rsa_private_key_pem_next"` // AUTH_JWT_RSA_PRIVATE_KEY_PEM_NEXT

	// RSAPrivateKeyPEMPrevious is an optional retiring key. Its public half
	// stays in JWKS so tokens signed by the prior Current key continue to
	// validate for the remainder of their TTL after rotation.
	RSAPrivateKeyPEMPrevious string `mapstructure:"rsa_private_key_pem_previous"` // AUTH_JWT_RSA_PRIVATE_KEY_PEM_PREVIOUS

	Issuer   string   `mapstructure:"issuer"`
	Audience []string `mapstructure:"audience"` // AUTH_JWT_AUDIENCE (comma-separated); included in all issued tokens per RFC 9068 §2.2

	// OIDCIssuer is the iss claim copied verbatim into ID tokens (OIDC §2)
	// and used as the platform identifier in RFC 8414 metadata. Per ADR-0010
	// it MUST be a URL — startup validation enforces the prefix. Defaults to
	// "" when AUTH_JWT_OIDC_ISSUER is unset; an empty value disables OIDC
	// mode entirely.
	OIDCIssuer string `mapstructure:"oidc_issuer"` // AUTH_JWT_OIDC_ISSUER

	// IDTokenTTLSeconds is the lifetime of issued ID tokens. Default 300
	// (5 minutes) per ADR-0010 — ID tokens are meant for immediate
	// consumption by the relying party, not long-lived API access.
	IDTokenTTLSeconds int `mapstructure:"id_token_ttl_seconds"` // AUTH_JWT_ID_TOKEN_TTL_SECONDS
}

// SigningAlg values.
const (
	SigningAlgRS256 = "RS256"
	SigningAlgHS256 = "HS256"
)

// TokenConfig holds token lifetime configuration.
type TokenConfig struct {
	TTLSeconds             int `mapstructure:"ttl_seconds"`
	RefreshTokenTTLSeconds int `mapstructure:"refresh_token_ttl_seconds"`
}

// AuthorizationCodeConfig holds the lifetime for OAuth 2.1 authorization
// codes (ADR-0009). The default of 60 seconds is the tight bound that limits
// the exfiltration-then-redeem window.
type AuthorizationCodeConfig struct {
	TTLSeconds int `mapstructure:"ttl_seconds"` // AUTH_AUTHORIZATION_CODE_TTL_SECONDS
}

// LoginChallengeConfig holds the lifetime for /oauth/authorize login
// challenges (ADR-0011). The default of 300 seconds is long enough for the
// user to read consent screens, short enough that abandoned challenges
// expire quickly.
type LoginChallengeConfig struct {
	TTLSeconds int `mapstructure:"ttl_seconds"` // AUTH_LOGIN_CHALLENGE_TTL_SECONDS
}

// PushedAuthorizationRequestConfig holds the lifetime for RFC 9126 pushed
// authorization requests (ADR-0021). The default of 90 seconds covers the
// round trip from POST /oauth/par to the redirect to /oauth/authorize with
// a narrow exploitation window if the request_uri leaks.
type PushedAuthorizationRequestConfig struct {
	TTLSeconds int `mapstructure:"ttl_seconds"` // AUTH_PAR_TTL_SECONDS
}

// DeviceAuthorizationConfig holds the lifetime and advertised polling
// interval for RFC 8628 device authorization requests (ADR-0022). The
// default 600-second TTL matches RFC 8628 §3.2's example; the 5-second
// interval is a typical CLI-friendly polling cadence.
type DeviceAuthorizationConfig struct {
	TTLSeconds          int `mapstructure:"ttl_seconds"`           // AUTH_DEVICE_AUTHORIZATION_TTL_SECONDS
	PollIntervalSeconds int `mapstructure:"poll_interval_seconds"` // AUTH_DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS
}

// LoginUIConfig holds the base URL for the login-ui service and the shared
// bearer token login-ui presents on /internal/issue-code. When URL is empty,
// /oauth/authorize returns 501 Not Implemented (preserves the pre-ADR-0011
// stub). When ServiceToken is empty, /internal/issue-code returns 404 even
// if URL is set — operators that have not minted a token have not opted in.
//
// ServiceToken must be a high-entropy random value (≥32 bytes hex) shared
// with login-ui's LOGIN_UI_SERVICE_TOKEN.
type LoginUIConfig struct {
	URL          string `mapstructure:"url"`           // AUTH_LOGIN_UI_URL
	ServiceToken string `mapstructure:"service_token"` // AUTH_LOGIN_UI_SERVICE_TOKEN
}

// PolicyConfig holds the URL for authorization-policy-service.
// When URL is empty, tokens are issued without roles/permissions claims.
type PolicyConfig struct {
	URL string `mapstructure:"url"` // AUTH_POLICY_URL
}

// IntrospectionConfig holds the pre-shared secret for the introspection endpoint.
// When Secret is set, callers must supply Authorization: Bearer <secret>.
// When empty, the endpoint requires client credentials (Basic Auth or form body).
type IntrospectionConfig struct {
	Secret string `mapstructure:"secret"` // AUTH_INTROSPECTION_SECRET
}

type LogConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Environment string `mapstructure:"environment"`
}

// ClientRegistryConfig holds the URL for client-registry-service.
// When URL is empty, auth-server falls back to its in-memory client store.
type ClientRegistryConfig struct {
	URL string `mapstructure:"url"` // AUTH_CLIENT_REGISTRY_URL
}

// IdentityServiceConfig holds the URL for identity-service.
// When URL is empty, the authorization_code grant remains a stub.
type IdentityServiceConfig struct {
	URL string `mapstructure:"url"` // AUTH_IDENTITY_SERVICE_URL
}

// AuditConfig configures the agent-audit emitter (ADR-0018 / ADR-0019).
// The emitter is always wired with the best-effort stderr JSON sink;
// the durable Postgres sink is added when DurableDSN is set.
type AuditConfig struct {
	// DurableDSN is the Postgres connection string for the
	// at-least-once durable audit sink. When empty, audit emission
	// is best-effort (stderr only) and accounting integrity cannot be
	// guaranteed — never deploy a billable environment without this.
	DurableDSN string `mapstructure:"durable_dsn"` // AUTH_AUDIT_DURABLE_DSN

	// SkipMigration disables the CREATE TABLE IF NOT EXISTS call at
	// startup. Default false. Set to true when a separate migration job
	// owns the audit_events schema.
	SkipMigration bool `mapstructure:"skip_migration"` // AUTH_AUDIT_SKIP_MIGRATION
}

// RedisConfig holds the connection details for the Redis token store.
// When URL is empty, auth-server falls back to an in-memory token repository.
// Note: the in-memory store is not safe for multi-replica deployments —
// see ADR-0005 and the horizontal scalability constraints in CLAUDE.md.
type RedisConfig struct {
	URL string `mapstructure:"url"` // AUTH_REDIS_URL
}

func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("jwt.signing_alg", SigningAlgRS256)
	v.SetDefault("jwt.signing_key", "")
	v.SetDefault("jwt.rsa_private_key_pem", "")
	v.SetDefault("jwt.rsa_private_key_pem_next", "")
	v.SetDefault("jwt.rsa_private_key_pem_previous", "")
	v.SetDefault("jwt.issuer", "identity-platform")
	v.SetDefault("jwt.oidc_issuer", "")           // AUTH_JWT_OIDC_ISSUER (ADR-0010) — empty disables OIDC (id_token, /userinfo)
	v.SetDefault("jwt.id_token_ttl_seconds", 300) // AUTH_JWT_ID_TOKEN_TTL_SECONDS (ADR-0010)
	v.SetDefault("token.ttl_seconds", 300)
	v.SetDefault("token.refresh_token_ttl_seconds", 604800)
	v.SetDefault("authorization_code.ttl_seconds", 60)            // ADR-0009 §"Authorization code shape"
	v.SetDefault("login_challenge.ttl_seconds", 300)              // ADR-0011 §"The login-challenge handoff"
	v.SetDefault("pushed_authorization_request.ttl_seconds", 90)  // ADR-0021, RFC 9126
	v.SetDefault("device_authorization.ttl_seconds", 600)         // ADR-0022 — RFC 8628 §3.2 example
	v.SetDefault("device_authorization.poll_interval_seconds", 5) // ADR-0022
	v.SetDefault("login_ui.url", "")
	v.SetDefault("login_ui.service_token", "")
	v.SetDefault("policy.url", "")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("client_registry.url", "")
	v.SetDefault("identity_service.url", "")
	v.SetDefault("redis.url", "")
	v.SetDefault("jwt.audience", []string{})
	v.SetDefault("introspection.secret", "")
	v.SetDefault("audit.durable_dsn", "")
	v.SetDefault("audit.skip_migration", false)
	v.SetDefault("metadata.public_base_url", "")
	v.SetDefault("metadata.service_documentation", "")
	v.SetDefault("metadata.registration_endpoint", "")
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.service_version", "")
	v.SetDefault("tracing.exporter_endpoint", "")
	v.SetDefault("tracing.exporter_protocol", "")
	v.SetDefault("tracing.exporter_insecure", false)
	v.SetDefault("tracing.sampler_ratio", 0.0)
	v.SetDefault("dev_seed_clients", false)
	v.SetDefault("dev_client_secret", "")

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("AUTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := validateJWTConfig(cfg.JWT); err != nil {
		return nil, fmt.Errorf("validating jwt config: %w", err)
	}
	return &cfg, nil
}

// validateJWTConfig enforces alg-specific rules. HS256 requires a strong shared
// secret. RS256 accepts an empty PEM (fall back to in-memory key generation at
// container startup) but rejects malformed PEM material — better to fail at
// Load() than to fail at first signing call.
func validateJWTConfig(cfg JWTConfig) error {
	switch cfg.SigningAlg {
	case SigningAlgRS256:
		return validateRS256Config(cfg)
	case SigningAlgHS256:
		return validateHS256SigningKey(cfg.SigningKey)
	default:
		return fmt.Errorf("unsupported jwt.signing_alg %q (want %q or %q)", cfg.SigningAlg, SigningAlgRS256, SigningAlgHS256)
	}
}

func validateRS256Config(cfg JWTConfig) error {
	for _, pemStr := range []struct {
		envVar string
		value  string
	}{
		{"AUTH_JWT_RSA_PRIVATE_KEY_PEM", cfg.RSAPrivateKeyPEM},
		{"AUTH_JWT_RSA_PRIVATE_KEY_PEM_NEXT", cfg.RSAPrivateKeyPEMNext},
		{"AUTH_JWT_RSA_PRIVATE_KEY_PEM_PREVIOUS", cfg.RSAPrivateKeyPEMPrevious},
	} {
		if pemStr.value == "" {
			continue
		}
		// Cheap structural check — the domain loader does the real parse and
		// 2048-bit floor check at container build time. Doing the parse here
		// would couple config to crypto/x509 unnecessarily.
		if !strings.Contains(pemStr.value, "-----BEGIN") {
			return fmt.Errorf("%s does not look like a PEM block (no BEGIN marker)", pemStr.envVar)
		}
	}
	return nil
}

func validateHS256SigningKey(key string) error {
	insecureDefaults := []string{"change-me-in-production", "default-signing-key"}
	for _, d := range insecureDefaults {
		if key == d {
			return fmt.Errorf("jwt.signing_key is insecure default; set AUTH_JWT_SIGNING_KEY to a random value of at least 32 characters")
		}
	}
	if len(key) < 32 {
		return fmt.Errorf("jwt.signing_key must be at least 32 characters; set AUTH_JWT_SIGNING_KEY")
	}
	return nil
}
