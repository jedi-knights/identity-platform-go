package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all client-registry-service configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Database DatabaseConfig `mapstructure:"database"`
	Audit    AuditConfig    `mapstructure:"audit"`
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
