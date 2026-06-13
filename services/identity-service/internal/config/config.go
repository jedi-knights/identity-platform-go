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
	Email    EmailConfig    `mapstructure:"email"`
}

// EmailConfig holds the email-sender configuration. The flow is:
//
//	sender:                  which adapter to use (stdout | noop)
//	verification_url_template: how the verification URL is rendered before
//	                           it is handed to the sender. Must contain
//	                           "{{token}}" — the application substitutes the
//	                           one-time token at send time.
//	token_ttl_secs:           how long a fresh verification token remains
//	                           redeemable. Defaults to 86400 (24 hours).
type EmailConfig struct {
	Sender                  string `mapstructure:"sender"`
	VerificationURLTemplate string `mapstructure:"verification_url_template"`
	TokenTTLSeconds         int    `mapstructure:"token_ttl_secs"`
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
	v.SetDefault("email.sender", "stdout")
	v.SetDefault("email.verification_url_template", "")
	v.SetDefault("email.token_ttl_secs", 86400) // 24h

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
