package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all identity-service configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Database DatabaseConfig `mapstructure:"database"`
}

// DatabaseConfig holds PostgreSQL connection settings.
// When URL is empty the service falls back to the in-memory repository adapter,
// which is appropriate for local development and reference use.
type DatabaseConfig struct {
	// URL is the full PostgreSQL DSN (e.g. postgres://user:pass@host:5432/dbname).
	// Populated from the IDENTITY_DATABASE_URL environment variable.
	URL string `mapstructure:"url"`
}

// ServerConfig holds HTTP server binding configuration.
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// LogConfig holds structured logging configuration.
type LogConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Environment string `mapstructure:"environment"`
}

func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8081)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("database.url", "")

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("IDENTITY")
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

	return &cfg, nil
}
