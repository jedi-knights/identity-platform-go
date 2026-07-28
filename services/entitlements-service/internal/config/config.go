// Package config holds entitlements-service's Viper-based configuration
// loader. Follows the identity-service pattern — same shape, ENTITLEMENTS_
// env prefix instead of IDENTITY_.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all entitlements-service configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Database DatabaseConfig `mapstructure:"database"`
	Audit    AuditConfig    `mapstructure:"audit"`
	Tracing  TracingConfig  `mapstructure:"tracing"`
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

// DatabaseConfig holds the entitlements Postgres DSN. When URL is empty
// the service falls back to the in-memory repository adapter — fine for
// development, unsafe for anything that must survive a restart.
type DatabaseConfig struct {
	URL string `mapstructure:"url"` // ENTITLEMENTS_DATABASE_URL
}

// AuditConfig configures the agent-audit emitter (ADR-0018 / ADR-0019).
// Mirrors identity-service's AuditConfig — durable Postgres sink added
// on top of the always-on stderr sink when DurableDSN is set.
type AuditConfig struct {
	DurableDSN    string `mapstructure:"durable_dsn"`    // ENTITLEMENTS_AUDIT_DURABLE_DSN
	SkipMigration bool   `mapstructure:"skip_migration"` // ENTITLEMENTS_AUDIT_SKIP_MIGRATION
}

// TracingConfig configures the OpenTelemetry SDK bootstrap.
type TracingConfig struct {
	Enabled          bool    `mapstructure:"enabled"`           // ENTITLEMENTS_TRACING_ENABLED
	ServiceVersion   string  `mapstructure:"service_version"`   // ENTITLEMENTS_TRACING_SERVICE_VERSION
	ExporterEndpoint string  `mapstructure:"exporter_endpoint"` // ENTITLEMENTS_TRACING_EXPORTER_ENDPOINT
	ExporterProtocol string  `mapstructure:"exporter_protocol"` // ENTITLEMENTS_TRACING_EXPORTER_PROTOCOL
	ExporterInsecure bool    `mapstructure:"exporter_insecure"` // ENTITLEMENTS_TRACING_EXPORTER_INSECURE
	SamplerRatio     float64 `mapstructure:"sampler_ratio"`     // ENTITLEMENTS_TRACING_SAMPLER_RATIO
}

// Load reads config from env / config file (config.yaml in cwd or
// ./config/) and returns a fully-populated Config.
func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8086)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "development")
	v.SetDefault("database.url", "")
	v.SetDefault("audit.durable_dsn", "")
	v.SetDefault("audit.skip_migration", false)
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.service_version", "")
	v.SetDefault("tracing.exporter_endpoint", "")
	v.SetDefault("tracing.exporter_protocol", "")
	v.SetDefault("tracing.exporter_insecure", false)
	v.SetDefault("tracing.sampler_ratio", 0.0)

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("ENTITLEMENTS")
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
