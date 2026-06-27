// Package config loads the login-ui service's runtime configuration via
// viper. Every variable is namespaced under LOGIN_UI_ at the env layer; the
// in-process mapping uses dotted keys (e.g. LOGIN_UI_SERVER_PORT →
// server.port) so the YAML form lines up with environment overrides.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config is the root of the login-ui configuration tree.
type Config struct {
	Server          ServerConfig          `mapstructure:"server"`
	Log             LogConfig             `mapstructure:"log"`
	AuthServer      AuthServerConfig      `mapstructure:"auth_server"`
	IdentityService IdentityServiceConfig `mapstructure:"identity_service"`
	Audit           AuditConfig           `mapstructure:"audit"`
}

// AuditConfig configures the agent-audit emitter (ADR-0018 / ADR-0019).
// The emitter is always wired with the best-effort stderr JSON sink;
// the durable Postgres sink is added when DurableDSN is set.
type AuditConfig struct {
	// DurableDSN is the Postgres connection string for the
	// at-least-once durable audit sink. When empty, audit emission
	// is best-effort (stderr only).
	DurableDSN string `mapstructure:"durable_dsn"` // LOGIN_UI_AUDIT_DURABLE_DSN

	// SkipMigration disables the CREATE TABLE IF NOT EXISTS call at
	// startup. Default false.
	SkipMigration bool `mapstructure:"skip_migration"` // LOGIN_UI_AUDIT_SKIP_MIGRATION
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

// AuthServerConfig holds settings for the inter-service call that login-ui
// makes to auth-server's /internal/issue-code after a successful sign-in.
// The ServiceToken is shared between the two services — see
// AUTH_LOGIN_UI_SERVICE_TOKEN on auth-server.
type AuthServerConfig struct {
	URL          string `mapstructure:"url"`           // LOGIN_UI_AUTH_SERVER_URL — e.g. http://auth-server:8080
	ServiceToken string `mapstructure:"service_token"` // LOGIN_UI_AUTH_SERVER_SERVICE_TOKEN
}

// IdentityServiceConfig holds the URL login-ui calls for credential
// verification (/auth/login) on identity-service.
type IdentityServiceConfig struct {
	URL string `mapstructure:"url"` // LOGIN_UI_IDENTITY_SERVICE_URL
}

// Load reads configuration from environment variables (LOGIN_UI_*) and
// the optional config.yaml file in the working directory. Returns the
// populated Config or an error if the YAML file is present but malformed.
// Missing optional values fall back to the defaults declared inline.
func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8087)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("auth_server.url", "")
	v.SetDefault("auth_server.service_token", "")
	v.SetDefault("identity_service.url", "")
	v.SetDefault("audit.durable_dsn", "")
	v.SetDefault("audit.skip_migration", false)

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("LOGIN_UI")
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
