package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all client-registry-service configuration.
type Config struct {
	Server       ServerConfig       `mapstructure:"server"`
	Log          LogConfig          `mapstructure:"log"`
	Database     DatabaseConfig     `mapstructure:"database"`
	Audit        AuditConfig        `mapstructure:"audit"`
	Registration RegistrationConfig `mapstructure:"registration"`
}

// RegistrationConfig configures the RFC 7591 dynamic client registration
// endpoint (ADR-0013). When PublicBaseURL is empty the /register route
// is not registered.
type RegistrationConfig struct {
	// PublicBaseURL is the absolute origin the registration endpoint
	// is reachable at from clients. Used to build the response's
	// registration_client_uri. Sourced from CLIENT_REGISTRATION_BASE_URL.
	PublicBaseURL string `mapstructure:"base_url"`

	// AllowedScopes is the comma-separated set of scopes a
	// dynamically-registered client may request. Each requested scope
	// must be in this set or registration fails with
	// invalid_client_metadata. Empty allows any scope (dev only).
	// Sourced from CLIENT_REGISTRATION_ALLOWED_SCOPES.
	AllowedScopes []string `mapstructure:"allowed_scopes"`

	// AllowLocalhost relaxes the redirect-URI / metadata URI scheme
	// check so http://localhost is accepted alongside https. Defaults
	// to false. Sourced from CLIENT_REGISTRATION_ALLOW_LOCALHOST.
	AllowLocalhost bool `mapstructure:"allow_localhost"`
}

// AuditConfig configures the agent-audit emitter (ADR-0018 / ADR-0019).
// The emitter is always wired with the best-effort stderr JSON sink;
// the durable Postgres sink is added when DurableDSN is set.
type AuditConfig struct {
	// DurableDSN is the Postgres connection string for the
	// at-least-once durable audit sink. When empty, audit emission
	// is best-effort (stderr only) and accounting integrity cannot be
	// guaranteed — never deploy a billable environment without this.
	DurableDSN string `mapstructure:"durable_dsn"` // CLIENT_AUDIT_DURABLE_DSN

	// SkipMigration disables the CREATE TABLE IF NOT EXISTS call at
	// startup. Default false. Set to true when a separate migration job
	// owns the audit_events schema.
	SkipMigration bool `mapstructure:"skip_migration"` // CLIENT_AUDIT_SKIP_MIGRATION
}

// DatabaseConfig holds database connection settings.
// When URL is empty the service falls back to the in-memory adapter so
// it can run in isolation without an external database.
type DatabaseConfig struct {
	// URL is the PostgreSQL connection string, sourced from CLIENT_DATABASE_URL.
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
	v.SetDefault("server.port", 8082)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("database.url", "")
	v.SetDefault("audit.durable_dsn", "")
	v.SetDefault("audit.skip_migration", false)
	v.SetDefault("registration.base_url", "")
	v.SetDefault("registration.allowed_scopes", []string{})
	v.SetDefault("registration.allow_localhost", false)

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("CLIENT")
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
