package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all auth-server configuration.
type Config struct {
	Server          ServerConfig `mapstructure:"server"`
	JWT             JWTConfig    `mapstructure:"jwt"`
	Token           TokenConfig  `mapstructure:"token"`
	Log             LogConfig    `mapstructure:"log"`
	DevSeedClients  bool         `mapstructure:"dev_seed_clients"`
	DevClientSecret string       `mapstructure:"dev_client_secret"` // AUTH_DEV_CLIENT_SECRET; only used when DevSeedClients=true
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type JWTConfig struct {
	SigningKey string `mapstructure:"signing_key"`
	Issuer     string `mapstructure:"issuer"`
}

type TokenConfig struct {
	TTLSeconds int `mapstructure:"ttl_seconds"`
}

type LogConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Environment string `mapstructure:"environment"`
}

func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("jwt.signing_key", "change-me-in-production")
	v.SetDefault("jwt.issuer", "identity-platform")
	v.SetDefault("token.ttl_seconds", 3600)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
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
