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
	Billing         BillingConfig         `mapstructure:"billing"`
	Tracing         TracingConfig         `mapstructure:"tracing"`
}

// TracingConfig configures the OpenTelemetry SDK bootstrap (ADR-0014 /
// portfolio observability roadmap). Every field is optional; missing
// values fall back to OTEL_* environment variables and ultimately to a
// stdout exporter so traces are visible during local development without
// a collector.
//
// Enabled controls whether the SDK is bootstrapped at all. When false
// the global TracerProvider stays as the no-op default and outbound
// otelhttp wrappers emit no spans — but the inbound otelhttp.NewHandler
// wrapper and the outbound otelhttp.NewTransport wrappers stay in the
// chain so flipping the flag at deploy time turns tracing on without
// code changes.
//
// login-ui is the multi-target hop in the trace graph: every sign-in
// fans out to identity-service and auth-server, and every billing call
// fans out to Lago (which talks to Stripe). Wrapping the shared
// http.Client transport with otelhttp.NewTransport is what makes the
// W3C traceparent header propagate to all four downstreams.
type TracingConfig struct {
	// Enabled toggles OTel bootstrap. Sourced from LOGIN_UI_TRACING_ENABLED.
	// Default false — opt-in until every dependent service ships the
	// same bootstrap and a collector is available.
	Enabled bool `mapstructure:"enabled"`

	// ServiceVersion is reported as the service.version resource
	// attribute. Sourced from LOGIN_UI_TRACING_SERVICE_VERSION; when empty
	// OTEL_SERVICE_VERSION is consulted.
	ServiceVersion string `mapstructure:"service_version"`

	// ExporterEndpoint overrides the OTLP endpoint. Empty defers to
	// OTEL_EXPORTER_OTLP_ENDPOINT; when that is also empty the SDK
	// falls back to a stdout exporter.
	ExporterEndpoint string `mapstructure:"exporter_endpoint"`

	// ExporterProtocol selects the OTLP transport ("grpc" or "http").
	// Empty defers to OTEL_EXPORTER_OTLP_PROTOCOL; default grpc.
	ExporterProtocol string `mapstructure:"exporter_protocol"`

	// ExporterInsecure disables TLS on the OTLP gRPC endpoint.
	ExporterInsecure bool `mapstructure:"exporter_insecure"`

	// SamplerRatio sets the head-based sampler ratio. Zero falls back
	// to 1 (sample every root span) inside the SDK; 0.1 keeps 10% of
	// traces.
	SamplerRatio float64 `mapstructure:"sampler_ratio"`
}

// BillingConfig configures the Lago billing client and the Stripe
// Checkout return URLs (ADR-0019). All fields are optional — when URL
// is empty the billing routes degrade to 503 and sign-in continues to
// work.
type BillingConfig struct {
	// LagoURL is the Lago API root (e.g. http://lago-api.internal).
	// Sourced from LOGIN_UI_BILLING_LAGO_URL. Empty disables billing.
	LagoURL string `mapstructure:"lago_url"`

	// LagoAPIKey authenticates Lago API calls. Sourced from
	// LOGIN_UI_BILLING_LAGO_API_KEY. Required when LagoURL is set.
	LagoAPIKey string `mapstructure:"lago_api_key"`

	// SuccessURL is where Stripe sends the user after Checkout completes.
	// Sourced from LOGIN_UI_BILLING_SUCCESS_URL.
	SuccessURL string `mapstructure:"success_url"`

	// CancelURL is where Stripe sends the user when they abandon Checkout.
	// Sourced from LOGIN_UI_BILLING_CANCEL_URL.
	CancelURL string `mapstructure:"cancel_url"`
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
	v.SetDefault("billing.lago_url", "")
	v.SetDefault("billing.lago_api_key", "")
	v.SetDefault("billing.success_url", "")
	v.SetDefault("billing.cancel_url", "")
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
