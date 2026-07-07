package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// DatabaseConfig holds the connection URL for the PostgreSQL persistence adapter.
// When URL is empty, the service falls back to in-memory storage.
type DatabaseConfig struct {
	URL string `mapstructure:"url"` // RESOURCE_DATABASE_URL
}

type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	Log           LogConfig           `mapstructure:"log"`
	JWT           JWTConfig           `mapstructure:"jwt"`
	Introspection IntrospectionConfig `mapstructure:"introspection"`
	Database      DatabaseConfig      `mapstructure:"database"`
	Policy        PolicyConfig        `mapstructure:"policy"`
	Tracing       TracingConfig       `mapstructure:"tracing"`
}

// TracingConfig configures the OpenTelemetry SDK bootstrap. Every field
// is optional; missing values fall back to OTEL_* environment variables
// and ultimately to a stdout exporter so traces are visible during
// local development without a collector.
//
// Enabled controls whether the SDK is bootstrapped at all. When false
// the global TracerProvider stays as the no-op default and the
// otelhttp wrappers on the router and outbound clients emit no spans.
type TracingConfig struct {
	Enabled          bool    `mapstructure:"enabled"`           // RESOURCE_TRACING_ENABLED
	ServiceVersion   string  `mapstructure:"service_version"`   // RESOURCE_TRACING_SERVICE_VERSION
	ExporterEndpoint string  `mapstructure:"exporter_endpoint"` // RESOURCE_TRACING_EXPORTER_ENDPOINT
	ExporterProtocol string  `mapstructure:"exporter_protocol"` // RESOURCE_TRACING_EXPORTER_PROTOCOL
	ExporterInsecure bool    `mapstructure:"exporter_insecure"` // RESOURCE_TRACING_EXPORTER_INSECURE
	SamplerRatio     float64 `mapstructure:"sampler_ratio"`     // RESOURCE_TRACING_SAMPLER_RATIO
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type LogConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Environment string `mapstructure:"environment"`
}

type JWTConfig struct {
	// SigningKey is the HS256 HMAC secret used for local validation when
	// neither JWKSURL nor IntrospectionURL is configured.
	SigningKey string `mapstructure:"signing_key"` // RESOURCE_JWT_SIGNING_KEY

	// JWKSURL is the auth-server JWKS document URL. When set, this service
	// validates tokens as RS256 against the discovered public keys. SigningKey
	// is ignored. Skipped entirely when IntrospectionURL is set (introspection
	// takes precedence since it also handles revocation).
	JWKSURL string `mapstructure:"jwks_url"` // RESOURCE_JWT_JWKS_URL

	// JWKSCacheTTL is how long a successful JWKS fetch is cached. Default 1h.
	JWKSCacheTTL string `mapstructure:"jwks_cache_ttl"` // RESOURCE_JWT_JWKS_CACHE_TTL

	// Audience is the expected audience value for locally-validated JWTs.
	// When set, tokens must carry a matching aud claim (RFC 9068 §4).
	// Maps to RESOURCE_JWT_AUDIENCE. Empty disables audience validation.
	Audience string `mapstructure:"audience"` // RESOURCE_JWT_AUDIENCE
	// Issuer is the expected iss claim for locally-validated JWTs (RFC 8725 §3.8).
	// When set, tokens whose iss claim does not match are rejected.
	// Maps to RESOURCE_JWT_ISSUER. Empty disables issuer validation.
	Issuer string `mapstructure:"issuer"` // RESOURCE_JWT_ISSUER
}

// IntrospectionConfig holds the URL and optional pre-shared secret for token-introspection-service.
// When URL is empty, the service falls back to local JWT validation.
type IntrospectionConfig struct {
	URL string `mapstructure:"url"` // RESOURCE_INTROSPECTION_URL
	// Secret is sent as Authorization: Bearer <secret> when calling token-introspection-service.
	// When empty, no auth header is sent. Must match INTROSPECT_SECRET_KEY on that service.
	Secret string `mapstructure:"secret"` // RESOURCE_INTROSPECTION_SECRET
}

// PolicyConfig holds the URL for authorization-policy-service.
// When URL is empty, policy evaluation is skipped and scope alone gates access.
type PolicyConfig struct {
	URL string `mapstructure:"url"` // RESOURCE_POLICY_URL
}

func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8085)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("jwt.signing_key", "")
	v.SetDefault("jwt.jwks_url", "")
	v.SetDefault("jwt.jwks_cache_ttl", "1h")
	v.SetDefault("jwt.audience", "")
	v.SetDefault("jwt.issuer", "")
	v.SetDefault("introspection.url", "")
	v.SetDefault("introspection.secret", "")
	v.SetDefault("database.url", "")
	v.SetDefault("policy.url", "")
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.service_version", "")
	v.SetDefault("tracing.exporter_endpoint", "")
	v.SetDefault("tracing.exporter_protocol", "")
	v.SetDefault("tracing.exporter_insecure", false)
	v.SetDefault("tracing.sampler_ratio", 0.0)

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("RESOURCE")
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

	// HS256 signing key is required only when neither introspection nor JWKS
	// is configured. The selection order at request time is:
	// 1. IntrospectionURL set → IntrospectionAuthMiddleware (handles revocation)
	// 2. JWKSURL set → RS256AuthMiddleware (local RS256 + JWKS)
	// 3. otherwise → JWTAuthMiddleware (legacy HS256 with shared secret)
	if cfg.Introspection.URL == "" && cfg.JWT.JWKSURL == "" {
		if err := validateSigningKey(cfg.JWT.SigningKey); err != nil {
			return nil, fmt.Errorf("validating jwt signing key: %w", err)
		}
	}
	return &cfg, nil
}

func validateSigningKey(key string) error {
	insecureDefaults := []string{"change-me-in-production", "default-signing-key"}
	for _, d := range insecureDefaults {
		if key == d {
			return fmt.Errorf("jwt.signing_key is insecure default; set RESOURCE_JWT_SIGNING_KEY to a random value of at least 32 characters")
		}
	}
	if len(key) < 32 {
		return fmt.Errorf("jwt.signing_key must be at least 32 characters; set RESOURCE_JWT_SIGNING_KEY")
	}
	return nil
}
