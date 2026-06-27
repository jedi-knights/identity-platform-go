package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the full runtime configuration for the authorization-policy-service.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Audit    AuditConfig    `mapstructure:"audit"`
}

// AuditConfig configures the agent-audit emitter (ADR-0018 / ADR-0019).
// The emitter is always wired with the best-effort stderr JSON sink;
// the durable Postgres sink is added when DurableDSN is set.
type AuditConfig struct {
	// DurableDSN is the Postgres connection string for the
	// at-least-once durable audit sink. When empty, audit emission
	// is best-effort (stderr only).
	DurableDSN string `mapstructure:"durable_dsn"` // POLICY_AUDIT_DURABLE_DSN

	// SkipMigration disables the CREATE TABLE IF NOT EXISTS call at
	// startup. Default false.
	SkipMigration bool `mapstructure:"skip_migration"` // POLICY_AUDIT_SKIP_MIGRATION
}

// DatabaseConfig holds database connection settings.
// When URL is empty the service falls back to in-memory adapters so the service
// can run without a database during local development.
type DatabaseConfig struct {
	// URL is the PostgreSQL connection string, read from POLICY_DATABASE_URL.
	// Example: postgres://user:password@localhost:5432/policy?sslmode=disable
	URL string `mapstructure:"url"`
}

// RedisConfig holds Redis connection settings for the caching layer.
// When URL is empty, Redis caching is disabled and every evaluation hits the
// backing store directly.
type RedisConfig struct {
	// URL is the Redis connection string, read from POLICY_REDIS_URL.
	// Example: redis://localhost:6379/0
	URL string `mapstructure:"url"`
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

func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8084)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("database.url", "")
	v.SetDefault("redis.url", "")
	v.SetDefault("audit.durable_dsn", "")
	v.SetDefault("audit.skip_migration", false)

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("POLICY")
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
