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
	SigningKey string `mapstructure:"signing_key"`
	// Audience is the expected audience value for locally-validated JWTs.
	// When set, tokens must carry a matching aud claim (RFC 9068 §4).
	// Maps to RESOURCE_JWT_AUDIENCE. Empty disables audience validation.
	Audience string `mapstructure:"audience"` // RESOURCE_JWT_AUDIENCE
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
	v.SetDefault("jwt.audience", "")
	v.SetDefault("introspection.url", "")
	v.SetDefault("introspection.secret", "")
	v.SetDefault("database.url", "")
	v.SetDefault("policy.url", "")

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

	// Signing key is required only when introspection service is not configured.
	if cfg.Introspection.URL == "" {
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
