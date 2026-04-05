package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all auth-server configuration.
type Config struct {
	Server          ServerConfig          `mapstructure:"server"`
	JWT             JWTConfig             `mapstructure:"jwt"`
	Token           TokenConfig           `mapstructure:"token"`
	Log             LogConfig             `mapstructure:"log"`
	ClientRegistry  ClientRegistryConfig  `mapstructure:"client_registry"`
	IdentityService IdentityServiceConfig `mapstructure:"identity_service"`
	Redis           RedisConfig           `mapstructure:"redis"`
	Policy          PolicyConfig          `mapstructure:"policy"`
	DevSeedClients  bool                  `mapstructure:"dev_seed_clients"`
	DevClientSecret string                `mapstructure:"dev_client_secret"` // AUTH_DEV_CLIENT_SECRET; only used when DevSeedClients=true
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type JWTConfig struct {
	SigningKey string `mapstructure:"signing_key"`
	Issuer     string `mapstructure:"issuer"`
}

// TokenConfig holds token lifetime configuration.
type TokenConfig struct {
	TTLSeconds             int `mapstructure:"ttl_seconds"`
	RefreshTokenTTLSeconds int `mapstructure:"refresh_token_ttl_seconds"`
}

// PolicyConfig holds the URL for authorization-policy-service.
// When URL is empty, tokens are issued without roles/permissions claims.
type PolicyConfig struct {
	URL string `mapstructure:"url"` // AUTH_POLICY_URL
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
	v.SetDefault("jwt.signing_key", "change-me-in-production")
	v.SetDefault("jwt.issuer", "identity-platform")
	v.SetDefault("token.ttl_seconds", 300)
	v.SetDefault("token.refresh_token_ttl_seconds", 604800)
	v.SetDefault("policy.url", "")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("client_registry.url", "")
	v.SetDefault("identity_service.url", "")
	v.SetDefault("redis.url", "")
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
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
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
	return &cfg, nil
}

func validateSigningKey(key string) error {
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
