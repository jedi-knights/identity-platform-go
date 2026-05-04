package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	Log           LogConfig           `mapstructure:"log"`
	JWT           JWTConfig           `mapstructure:"jwt"`
	Redis         RedisConfig         `mapstructure:"redis"`
	Introspection IntrospectionConfig `mapstructure:"introspection"`
}

// IntrospectionConfig holds the pre-shared secret for the introspection endpoint.
// Callers must supply Authorization: Bearer <secret>. RFC 7662 §2.1 requires some
// form of caller authentication on this endpoint; an empty secret is rejected at
// startup. Set via INTROSPECT_INTROSPECTION_SECRET.
type IntrospectionConfig struct {
	Secret string `mapstructure:"secret"` // INTROSPECT_INTROSPECTION_SECRET
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
	// Issuer is the expected iss claim value for tokens validated by this service.
	// When set, tokens whose iss claim does not match are treated as inactive (RFC 8725 §3.8).
	// Maps to INTROSPECT_JWT_ISSUER. Empty disables issuer validation.
	Issuer string `mapstructure:"issuer"` // INTROSPECT_JWT_ISSUER
}

// RedisConfig holds connection settings for the optional Redis revocation store.
// When URL is empty, revocation checking is disabled and tokens are accepted until JWT expiry.
// The URL is read from INTROSPECT_REDIS_URL.
type RedisConfig struct {
	URL string `mapstructure:"url"` // e.g. redis://localhost:6379/0
}

func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8083)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("jwt.signing_key", "")
	v.SetDefault("jwt.issuer", "")
	v.SetDefault("redis.url", "")
	v.SetDefault("introspection.secret", "")

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("INTROSPECT")
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

	if err := validateSigningKey(cfg.JWT.SigningKey); err != nil {
		return nil, err
	}
	if cfg.Introspection.Secret == "" {
		return nil, fmt.Errorf("validating introspection secret: INTROSPECT_INTROSPECTION_SECRET must not be empty — RFC 7662 §2.1 requires caller authentication on the introspection endpoint")
	}
	return &cfg, nil
}

func validateSigningKey(key string) error {
	if key == "" {
		return fmt.Errorf("validating signing key: INTROSPECT_JWT_SIGNING_KEY is not set")
	}
	insecureDefaults := []string{"change-me-in-production", "default-signing-key"}
	for _, d := range insecureDefaults {
		if key == d {
			return fmt.Errorf("validating signing key: insecure default value; set INTROSPECT_JWT_SIGNING_KEY to a random value of at least 32 characters")
		}
	}
	if len(key) < 32 {
		return fmt.Errorf("validating signing key: must be at least 32 characters; set INTROSPECT_JWT_SIGNING_KEY")
	}
	return nil
}
