package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// defaultMCPModel is used when no model is explicitly configured.
const defaultMCPModel = "claude-sonnet-4-6"

// AuthConfig governs JWT Bearer token authentication for API traffic.
// When Enabled is false the middleware is not added to the chain.
//
// Type selects the token-verification algorithm:
//   - "hs256" (default) — HMAC-SHA256; requires SigningKey.
//   - "jwks"            — RS256 via a JWKS endpoint; requires JWKSURL.
//
// SigningKey is the HMAC-SHA256 secret for the hs256 type.
// Inject it via GATEWAY_AUTH_SIGNING_KEY rather than storing it here.
//
// JWKSURL is the HTTPS URL of the JWKS endpoint (e.g. "https://auth.example.com/.well-known/jwks.json").
// Used only when Type is "jwks". The key set is cached and refreshed in the background.
//
// JWKSRefreshSecs controls how often the JWKS key set is re-fetched (default: 300).
//
// Issuer and Audience, when non-empty, are validated against the token's iss and aud claims.
// They apply to both hs256 and jwks types. Leave empty to skip the respective check.
//
// PublicPaths lists path prefixes that bypass token validation. X-Auth-* headers are
// still stripped on these paths to prevent clients from spoofing upstream identity.
type AuthConfig struct {
	Enabled         bool     `mapstructure:"enabled"`
	Type            string   `mapstructure:"type"`              // "hs256" | "jwks"
	SigningKey      string   `mapstructure:"signing_key"`       // hs256 only
	JWKSURL         string   `mapstructure:"jwks_url"`          // jwks only
	JWKSRefreshSecs int      `mapstructure:"jwks_refresh_secs"` // jwks only
	Issuer          string   `mapstructure:"issuer"`            // optional
	Audience        string   `mapstructure:"audience"`          // optional
	PublicPaths     []string `mapstructure:"public_paths"`
}

// TLSConfig holds per-upstream mTLS settings.
// A zero-value TLSConfig means no custom TLS — the shared default http.Client is used.
type TLSConfig struct {
	// CAFile is the path to a PEM-encoded CA certificate that verifies the upstream's
	// certificate. Empty means the system certificate pool is used.
	CAFile string `mapstructure:"ca_file"`

	// CertFile and KeyFile are the PEM-encoded client certificate and private key
	// for mutual TLS. Both must be set together; either alone is rejected at startup.
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`

	// InsecureSkipVerify disables upstream certificate verification.
	// Never enable in production; provided for local development only.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
}

// TracingConfig governs distributed tracing via OpenTelemetry.
// When Enabled is false, a no-op TracerProvider is used and no spans are exported.
//
// Exporter selects the span exporter:
//   - "stdout" — pretty-prints spans to stdout (development / debugging)
//   - "otlp"   — sends spans to an OpenTelemetry collector via OTLP/HTTP
//
// ServiceName is the OTel resource attribute "service.name" attached to every span.
// It appears in tracing UIs (Jaeger, Zipkin, Grafana Tempo) to identify the emitter.
//
// OTLPEndpoint is the host:port of the OTLP/HTTP collector (e.g. "otel-collector:4318").
// Ignored when Exporter is not "otlp". The env var OTEL_EXPORTER_OTLP_ENDPOINT also
// controls this and takes precedence over the config-file value when both are set.
type TracingConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	ServiceName  string `mapstructure:"service_name"`
	Exporter     string `mapstructure:"exporter"`
	OTLPEndpoint string `mapstructure:"otlp_endpoint"`
}

// CircuitBreakerConfig governs the per-route circuit breaker.
// When Enabled is false no circuit breaking is applied.
//
// The circuit breaker implements the standard three-state machine:
//   - Closed:    requests pass through; failures are counted.
//   - Open:      requests are rejected immediately with 503 Service Unavailable.
//     The breaker stays open for TimeoutSecs before retrying.
//   - Half-Open: MaxRequests probing requests are let through to test recovery.
//     Failures re-open; successes close the circuit.
//
// IntervalSecs is the rolling window for the failure counter in Closed state.
// A value of 0 means the counter resets only when the circuit transitions states.
type CircuitBreakerConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	MaxRequests  uint32  `mapstructure:"max_requests"`
	IntervalSecs int     `mapstructure:"interval_secs"`
	TimeoutSecs  int     `mapstructure:"timeout_secs"`
	FailureRatio float64 `mapstructure:"failure_ratio"`
}

// IPFilterConfig controls IP-based access control applied to every proxied request.
// When Enabled is false the middleware is not added to the chain.
//
// Mode "allow" means only CIDRs in the list are permitted; all others get 403.
// Mode "deny" means CIDRs in the list are blocked; all others are permitted.
//
// KeySource selects which part of the request is used to derive the client IP.
// It shares the same semantics as RateLimitConfig.KeySource.
type IPFilterConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Mode      string   `mapstructure:"mode"` // allow | deny
	CIDRs     []string `mapstructure:"cidrs"`
	KeySource string   `mapstructure:"key_source"` // ip | x-forwarded-for | x-real-ip | header:<name> | jwt-subject
}

// CompressionConfig controls gzip response compression.
// When Enabled is false the middleware is not added to the chain.
//
// MinSizeBytes sets the minimum response body size that triggers compression.
// Responses smaller than this threshold are sent uncompressed to avoid the CPU
// overhead outweighing the bandwidth saving.
//
// Level is the gzip compression level (1–9). 1 is fastest/least compressed;
// 9 is slowest/most compressed. The default of 6 balances speed and ratio.
type CompressionConfig struct {
	Enabled      bool `mapstructure:"enabled"`
	MinSizeBytes int  `mapstructure:"min_size_bytes"`
	Level        int  `mapstructure:"level"`
}

// CacheConfig controls response caching for proxied GET and HEAD requests.
// When Enabled is false the cache middleware is not added to the chain.
//
// MaxEntries is the maximum number of responses held in the LRU cache.
// When full, the least-recently-used entry is evicted before storing a new one.
//
// DefaultTTLSecs is the time-to-live for a cached entry. Per-route cache_ttl_secs
// overrides this on a per-route basis. Expired entries are removed on the next access.
type CacheConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	MaxEntries     int  `mapstructure:"max_entries"`
	DefaultTTLSecs int  `mapstructure:"default_ttl_secs"`
}

// RetryConfig governs automatic request retries on transient upstream failures.
// When Enabled is false no retries are attempted.
//
// MaxAttempts is the total number of attempts including the initial try, so
// MaxAttempts=3 means the initial request plus up to two retries.
//
// Backoff grows exponentially: delay = InitialBackoffMs × Multiplier^(attempt-1).
// The delay is capped at 30 s per attempt.
//
// RetryableStatus lists HTTP response status codes treated as transient failures
// that warrant a retry. Defaults: [502, 503, 504].
type RetryConfig struct {
	Enabled          bool    `mapstructure:"enabled"`
	MaxAttempts      int     `mapstructure:"max_attempts"`
	InitialBackoffMs int     `mapstructure:"initial_backoff_ms"`
	Multiplier       float64 `mapstructure:"multiplier"`
	RetryableStatus  []int   `mapstructure:"retryable_status"`
}

// MCPConfig holds configuration for the MCP tool-routing capability.
// AnthropicAPIKey and JWTSigningKey are loaded from environment variables
// (GATEWAY_MCP_ANTHROPIC_API_KEY, GATEWAY_MCP_JWT_SIGNING_KEY) and must never
// be set in the YAML config file.
type MCPConfig struct {
	AnthropicAPIKey string                       `mapstructure:"anthropic_api_key"`
	Model           string                       `mapstructure:"model"`
	JWTSigningKey   string                       `mapstructure:"jwt_signing_key"`
	Tools           []MCPToolConfig              `mapstructure:"tools"`
	ClientTiers     map[string]string            `mapstructure:"client_tiers"`
	RateLimits      map[string]MCPTierRateConfig `mapstructure:"rate_limits"`
}

// MCPToolConfig is the config-layer representation of a single registered tool.
type MCPToolConfig struct {
	Name        string `mapstructure:"name"`
	Tier        string `mapstructure:"tier"`
	RateGroup   string `mapstructure:"rate_group"`
	Description string `mapstructure:"description"`
	UpstreamURL string `mapstructure:"upstream_url"`
}

// MCPTierRateConfig defines rate limits for a single user tier.
type MCPTierRateConfig struct {
	WindowSeconds int                       `mapstructure:"window_seconds"`
	Limit         int                       `mapstructure:"limit"`
	Groups        map[string]MCPGroupConfig `mapstructure:"groups"`
}

// MCPGroupConfig defines the limit for a single named rate group.
type MCPGroupConfig struct {
	Limit int `mapstructure:"limit"`
}

// Config holds all api-gateway configuration.
type Config struct {
	Server         ServerConfig         `mapstructure:"server"`
	Log            LogConfig            `mapstructure:"log"`
	CORS           CORSConfig           `mapstructure:"cors"`
	Auth           AuthConfig           `mapstructure:"auth"`
	RateLimit      RateLimitConfig      `mapstructure:"rate_limit"`
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
	Tracing        TracingConfig        `mapstructure:"tracing"`
	IPFilter       IPFilterConfig       `mapstructure:"ip_filter"`
	Compression    CompressionConfig    `mapstructure:"compression"`
	Cache          CacheConfig          `mapstructure:"cache"`
	Retry          RetryConfig          `mapstructure:"retry"`
	MCP            MCPConfig            `mapstructure:"mcp"`
	Routes         []RouteConfig        `mapstructure:"routes"`
}

// CORSConfig holds Cross-Origin Resource Sharing settings.
// Governs which browser origins may call the gateway and with which methods/headers.
type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
	MaxAgeSecs     int      `mapstructure:"max_age_secs"`
}

// RateLimitConfig governs the rate limiter applied to API traffic.
// When Enabled is false the rate limiter is skipped entirely.
//
// Strategy selects the algorithm:
//   - "token_bucket"         — (default) allows bursts up to BurstSize; good general-purpose choice
//   - "fixed_window"         — counts requests in non-overlapping windows; simple but has boundary spike
//   - "sliding_window_log"   — per-request timestamp log; most accurate, O(N) memory per client
//   - "sliding_window_counter" — two-counter interpolation; O(1) memory, ~0.003% error (Cloudflare algorithm)
//   - "leaky_bucket"         — reject-only; enforces constant drain rate, no bursts
//   - "concurrency"          — limits simultaneous in-flight requests per key, not rate
//
// KeySource selects which part of the request identifies the client:
//   - "ip"              — RemoteAddr (default; broken behind a load balancer)
//   - "x-forwarded-for" — first IP in the X-Forwarded-For header; fallback to ip
//   - "x-real-ip"       — X-Real-IP header value; fallback to ip
//   - "header:<name>"   — arbitrary header value, e.g. "header:X-API-Key"
//   - "jwt-subject"     — X-Auth-Subject header injected by JWTMiddleware
//
// Token bucket parameters (strategy: "token_bucket"):
//
//	RequestsPerSecond — steady-state refill rate; BurstSize — max token accumulation.
//
// Window parameters (strategy: "fixed_window", "sliding_window_log", "sliding_window_counter"):
//
//	RequestsPerWindow — max requests allowed; WindowSecs — window size in seconds.
//
// Leaky bucket parameters (strategy: "leaky_bucket"):
//
//	DrainRatePerSecond — tokens drained per second; QueueDepth — virtual queue capacity.
//
// Concurrency parameters (strategy: "concurrency"):
//
//	MaxInFlight — maximum simultaneous in-flight requests per key.
type RateLimitConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Strategy  string `mapstructure:"strategy"`   // GATEWAY_RATE_LIMIT_STRATEGY
	KeySource string `mapstructure:"key_source"` // GATEWAY_RATE_LIMIT_KEY_SOURCE

	// Token bucket
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	BurstSize         int     `mapstructure:"burst_size"`

	// Window-based (fixed_window, sliding_window_log, sliding_window_counter)
	RequestsPerWindow int `mapstructure:"requests_per_window"`
	WindowSecs        int `mapstructure:"window_secs"`

	// Leaky bucket
	DrainRatePerSecond float64 `mapstructure:"drain_rate_per_second"`
	QueueDepth         int     `mapstructure:"queue_depth"`

	// Concurrency
	MaxInFlight int `mapstructure:"max_in_flight"`
}

// ServerConfig holds HTTP listener settings.
//
// TLS is opt-in: both TLSCertFile and TLSKeyFile must be set to enable HTTPS.
// When only one is set, validation fails at startup. Leave both empty for HTTP.
//
// DrainTimeoutSecs is the Phase 1 grace period of the two-phase shutdown:
// after the readiness probe fails (stopping new LB traffic), the gateway sleeps
// this many seconds to let the load balancer drain in-flight connections before
// the HTTP server begins rejecting new requests.
type ServerConfig struct {
	Host             string `mapstructure:"host"`
	Port             int    `mapstructure:"port"`
	TLSCertFile      string `mapstructure:"tls_cert_file"`
	TLSKeyFile       string `mapstructure:"tls_key_file"`
	DrainTimeoutSecs int    `mapstructure:"drain_timeout_secs"`
}

// LogConfig holds structured logging settings.
type LogConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Environment string `mapstructure:"environment"`
}

// RouteConfig is the configuration representation of a single routing rule.
// It is separate from domain.Route so that config concerns (YAML tags,
// validation) do not leak into the domain layer.
type RouteConfig struct {
	Name     string         `mapstructure:"name"`
	Match    MatchConfig    `mapstructure:"match"`
	Upstream UpstreamConfig `mapstructure:"upstream"`
}

// MatchConfig mirrors domain.MatchCriteria for configuration purposes.
type MatchConfig struct {
	PathPrefix string            `mapstructure:"path_prefix"`
	Methods    []string          `mapstructure:"methods"`
	Headers    map[string]string `mapstructure:"headers"`
}

// WeightedURL is a URL with a relative routing weight used for weighted load balancing.
// Higher weight means the URL receives proportionally more traffic.
// Entries with weight ≤ 0 are ignored.
type WeightedURL struct {
	URL    string `mapstructure:"url"`
	Weight int    `mapstructure:"weight"`
}

// HeaderRules is a set of header manipulation operations. Operations are applied
// in order: Remove first (delete entirely), then Set (overwrite), then Add (if absent).
type HeaderRules struct {
	Add    map[string]string `mapstructure:"add"`    // write header if not present
	Set    map[string]string `mapstructure:"set"`    // always set / overwrite
	Remove []string          `mapstructure:"remove"` // remove header entirely
}

// HeaderTransformConfig groups request and response header manipulation rules.
// Request rules are applied before forwarding to the upstream; response rules
// are applied before returning the response to the client.
type HeaderTransformConfig struct {
	Request  HeaderRules `mapstructure:"request"`
	Response HeaderRules `mapstructure:"response"`
}

// UpstreamConfig mirrors domain.UpstreamTarget for configuration purposes.
type UpstreamConfig struct {
	// URL is the single upstream endpoint. Ignored when URLs or WeightedURLs is set.
	// Kept for backward compatibility with single-upstream configurations.
	URL string `mapstructure:"url"`

	// URLs is the pool of upstream endpoints for round-robin load balancing.
	// Ignored when WeightedURLs is set. URL is ignored when URLs is set.
	// Example:
	//   urls:
	//     - "http://svc-1:8080"
	//     - "http://svc-2:8080"
	URLs []string `mapstructure:"urls"`

	// WeightedURLs is the pool with per-entry weights for weighted load balancing.
	// When set, URL and URLs are ignored. Entries with weight ≤ 0 are skipped.
	// Relative weights govern distribution: {weight:2} gets twice the traffic of {weight:1}.
	// Example:
	//   weighted_urls:
	//     - url: "http://svc-primary:8080"
	//       weight: 3
	//     - url: "http://svc-canary:8080"
	//       weight: 1
	WeightedURLs []WeightedURL `mapstructure:"weighted_urls"`

	StripPrefix string `mapstructure:"strip_prefix"`

	// TimeoutSecs is the per-route request deadline in seconds.
	// 0 means no route-level timeout; the shared http.Client timeout (30s) applies.
	TimeoutSecs int `mapstructure:"timeout_secs"`

	// WebSocket enables streaming / upgrade support for this upstream.
	// When true, the reverse proxy flushes response bytes immediately (FlushInterval: -1),
	// which is required for HTTP/1.1 upgrade handshakes (WebSocket, SSE, gRPC-web).
	WebSocket bool `mapstructure:"websocket"`

	// CacheTTLSecs overrides the global cache.default_ttl_secs for this route.
	// 0 means use the global default. Only applies when the global cache is enabled.
	CacheTTLSecs int `mapstructure:"cache_ttl_secs"`

	// Retry overrides the global retry policy for this route.
	// A per-route Retry with MaxAttempts > 0 takes precedence over the global config.
	// Set MaxAttempts=1 with Enabled=true to explicitly disable retries for this route.
	Retry RetryConfig `mapstructure:"retry"`

	// HeaderTransform applies header manipulation rules for this route.
	// Request rules mutate outgoing headers before forwarding to the upstream.
	// Response rules mutate incoming headers before returning to the client.
	HeaderTransform HeaderTransformConfig `mapstructure:"header_transform"`

	// TLS configures per-upstream mTLS for this route.
	// A zero-value TLS uses the shared default http.Client (no custom TLS).
	// Both cert_file and key_file must be set together for client authentication.
	TLS TLSConfig `mapstructure:"tls"`
}

// Load reads configuration from environment variables and, if present, from a
// YAML config file. Environment variables are prefixed with GATEWAY_ and use
// underscores as separators (e.g. GATEWAY_SERVER_PORT overrides server.port).
//
// Config file search order:
//  1. Path in GATEWAY_CONFIG_FILE env var
//  2. ./gateway.yaml (current working directory)
//  3. /etc/gateway/gateway.yaml
//
// Missing config files are silently ignored; all settings have defaults.
// Use LoadWithViper to supply a pre-configured Viper instance (e.g. one with
// Cobra flag bindings already applied).
func Load() (*Config, error) {
	return LoadWithViper(viper.New())
}

// LoadWithViper is the primary loader. It applies defaults and env bindings to v,
// then reads the config file and unmarshals into Config. Passing a Viper instance
// that already has Cobra pflags bound means CLI flags take precedence over env
// vars which take precedence over the config file which takes precedence over
// defaults — the standard Viper priority chain.
func LoadWithViper(v *viper.Viper) (*Config, error) {
	setDefaults(v)
	bindEnv(v)

	v.SetConfigName("gateway")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/gateway")

	if cfgFile := v.GetString("config_file"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.tls_cert_file", "")
	v.SetDefault("server.tls_key_file", "")
	// 5 s lets most load balancers finish draining before the HTTP server stops
	// accepting new connections. Override to 0 to disable the drain sleep.
	v.SetDefault("server.drain_timeout_secs", 5)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "production")

	// Auth is opt-in. type defaults to "hs256" (HMAC-SHA256).
	// For JWKS/OIDC, set type="jwks" and provide jwks_url.
	v.SetDefault("auth.enabled", false)
	v.SetDefault("auth.type", "hs256")
	v.SetDefault("auth.signing_key", "")
	v.SetDefault("auth.jwks_url", "")
	v.SetDefault("auth.jwks_refresh_secs", 300)
	v.SetDefault("auth.issuer", "")
	v.SetDefault("auth.audience", "")
	v.SetDefault("auth.public_paths", []string{})

	// Rate limiting is opt-in. The defaults are conservative but production-ready:
	// 100 req/s with a burst of 200 allows short spikes without overwhelming upstreams.
	// key_source defaults to "ip"; production deployments behind an LB should use
	// "x-forwarded-for" or "x-real-ip" so each end-user gets their own bucket.
	v.SetDefault("rate_limit.enabled", false)
	v.SetDefault("rate_limit.strategy", "token_bucket")
	v.SetDefault("rate_limit.key_source", "ip")
	// Token bucket defaults
	v.SetDefault("rate_limit.requests_per_second", 100.0)
	v.SetDefault("rate_limit.burst_size", 200)
	// Window-based defaults
	v.SetDefault("rate_limit.requests_per_window", 100)
	v.SetDefault("rate_limit.window_secs", 60)
	// Leaky bucket defaults
	v.SetDefault("rate_limit.drain_rate_per_second", 100.0)
	v.SetDefault("rate_limit.queue_depth", 200)
	// Concurrency defaults
	v.SetDefault("rate_limit.max_in_flight", 100)

	// IP filter is opt-in. Default mode is "deny" (block listed CIDRs).
	v.SetDefault("ip_filter.enabled", false)
	v.SetDefault("ip_filter.mode", "deny")
	v.SetDefault("ip_filter.cidrs", []string{})
	v.SetDefault("ip_filter.key_source", "ip")

	// Compression is opt-in. min_size_bytes=1024 avoids compressing tiny payloads
	// where the gzip header overhead would exceed the savings. Level 6 is the
	// standard gzip default — good balance of speed and compression ratio.
	v.SetDefault("compression.enabled", false)
	v.SetDefault("compression.min_size_bytes", 1024)
	v.SetDefault("compression.level", 6)

	// Distributed tracing via OpenTelemetry. Disabled by default; set enabled=true
	// and exporter="stdout" to emit spans to stdout during local development.
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.service_name", "api-gateway")
	v.SetDefault("tracing.exporter", "stdout")

	// Circuit breaking is opt-in. Defaults model a conservative policy:
	// open after 60% failure rate, retry after 30 s, allow one probe in half-open.
	v.SetDefault("circuit_breaker.enabled", false)
	v.SetDefault("circuit_breaker.max_requests", 1)
	v.SetDefault("circuit_breaker.interval_secs", 60)
	v.SetDefault("circuit_breaker.timeout_secs", 30)
	v.SetDefault("circuit_breaker.failure_ratio", 0.6)

	// Response caching is opt-in. max_entries=1000 limits memory to roughly a few MB
	// for typical API responses. default_ttl_secs=60 matches common upstream max-age.
	v.SetDefault("cache.enabled", false)
	v.SetDefault("cache.max_entries", 1000)
	v.SetDefault("cache.default_ttl_secs", 60)

	// Retries are opt-in. 3 attempts with 100 ms initial backoff, 2× multiplier.
	// Retryable statuses cover the standard transient upstream errors (502/503/504).
	v.SetDefault("retry.enabled", false)
	v.SetDefault("retry.max_attempts", 3)
	v.SetDefault("retry.initial_backoff_ms", 100)
	v.SetDefault("retry.multiplier", 2.0)
	v.SetDefault("retry.retryable_status", []int{502, 503, 504})

	// MCP model defaults to claude-sonnet-4-6 when not explicitly configured.
	v.SetDefault("mcp.model", defaultMCPModel)
}

// envPrefix is the environment variable prefix used by bindEnv.
// All config fields are addressable as GATEWAY_<SECTION>_<KEY> (dots → underscores).
const envPrefix = "GATEWAY"

func bindEnv(v *viper.Viper) {
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
}

// validate checks that the loaded configuration is consistent.
func validate(cfg *Config) error {
	if err := validateServer(cfg.Server); err != nil {
		return err
	}
	if err := validateRateLimit(cfg.RateLimit); err != nil {
		return err
	}
	if err := validateRoutes(cfg.Routes); err != nil {
		return err
	}
	return validateMCPTools(cfg.MCP.Tools)
}

// validateRoutes checks that each route has a unique name and a non-empty upstream URL.
func validateRoutes(routes []RouteConfig) error {
	seen := make(map[string]struct{}, len(routes))
	for i, r := range routes {
		if r.Name == "" {
			return fmt.Errorf("routes[%d]: name is required", i)
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("routes[%d]: duplicate route name %q", i, r.Name)
		}
		seen[r.Name] = struct{}{}
		if err := validateUpstream(i, r.Name, r.Upstream); err != nil {
			return err
		}
	}
	return nil
}

// validRateLimitStrategies is the set of recognised rate_limit.strategy values.
var validRateLimitStrategies = map[string]bool{
	"token_bucket": true, "fixed_window": true,
	"sliding_window_log": true, "sliding_window_counter": true,
	"leaky_bucket": true, "concurrency": true,
}

// validateRateLimit checks that, when rate limiting is enabled, the strategy
// is recognised and the per-strategy parameters are sensible.
// Extracted from validate to keep its cyclomatic complexity within the project limit.
func validateRateLimit(rl RateLimitConfig) error {
	if !rl.Enabled {
		return nil
	}
	if !validRateLimitStrategies[rl.Strategy] {
		return fmt.Errorf("rate_limit.strategy %q is not recognised; valid values: token_bucket, fixed_window, sliding_window_log, sliding_window_counter, leaky_bucket, concurrency", rl.Strategy)
	}
	return validateRateLimitParams(rl)
}

// validateRateLimitParams dispatches per-strategy parameter validation.
// Extracted from validateRateLimit to keep its cyclomatic complexity within limit.
func validateRateLimitParams(rl RateLimitConfig) error {
	switch rl.Strategy {
	case "token_bucket":
		return validateTokenBucketParams(rl)
	case "fixed_window", "sliding_window_log", "sliding_window_counter":
		return validateWindowParams(rl)
	case "leaky_bucket":
		return validateLeakyBucketParams(rl)
	case "concurrency":
		return validateConcurrencyParams(rl)
	}
	// Unreachable: validateRateLimit already checked validRateLimitStrategies before
	// calling here, so every valid strategy is handled by a case above.
	return nil
}

func validateTokenBucketParams(rl RateLimitConfig) error {
	if rl.RequestsPerSecond <= 0 {
		return fmt.Errorf("rate_limit.requests_per_second must be > 0 for strategy %q", rl.Strategy)
	}
	if rl.BurstSize <= 0 {
		return fmt.Errorf("rate_limit.burst_size must be > 0 for strategy %q", rl.Strategy)
	}
	return nil
}

func validateWindowParams(rl RateLimitConfig) error {
	if rl.RequestsPerWindow <= 0 {
		return fmt.Errorf("rate_limit.requests_per_window must be > 0 for strategy %q", rl.Strategy)
	}
	if rl.WindowSecs <= 0 {
		return fmt.Errorf("rate_limit.window_secs must be > 0 for strategy %q", rl.Strategy)
	}
	return nil
}

func validateLeakyBucketParams(rl RateLimitConfig) error {
	if rl.DrainRatePerSecond <= 0 {
		return fmt.Errorf("rate_limit.drain_rate_per_second must be > 0 for strategy %q", rl.Strategy)
	}
	if rl.QueueDepth <= 0 {
		return fmt.Errorf("rate_limit.queue_depth must be > 0 for strategy %q", rl.Strategy)
	}
	return nil
}

func validateConcurrencyParams(rl RateLimitConfig) error {
	if rl.MaxInFlight <= 0 {
		return fmt.Errorf("rate_limit.max_in_flight must be > 0 for strategy %q", rl.Strategy)
	}
	return nil
}

// validateServer checks server-level constraints: port range and TLS pairing.
// Extracted from validate to keep its cyclomatic complexity within the project limit.
func validateServer(s ServerConfig) error {
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("server.port %d is out of range [1, 65535]", s.Port)
	}
	// TLS requires both cert and key — one without the other is a misconfiguration.
	if (s.TLSCertFile == "") != (s.TLSKeyFile == "") {
		return fmt.Errorf("server.tls_cert_file and server.tls_key_file must both be set or both be empty")
	}
	return nil
}

// validateUpstream checks that a route's upstream has at least one configured URL
// and that its TLS settings are consistent.
// Extracted to keep validate's cyclomatic complexity within the project limit of 7.
func validateUpstream(idx int, name string, up UpstreamConfig) error {
	if up.URL == "" && len(up.URLs) == 0 && len(up.WeightedURLs) == 0 {
		return fmt.Errorf("routes[%d] (%q): upstream.url, upstream.urls, or upstream.weighted_urls is required", idx, name)
	}
	if err := validateUpstreamTLS(up.TLS); err != nil {
		return fmt.Errorf("routes[%d] (%q): %w", idx, name, err)
	}
	return nil
}

// validateUpstreamTLS rejects contradictory TLS settings on an upstream.
// Setting insecure_skip_verify alongside ca_file is meaningless — the custom CA
// is ignored when verification is disabled — and almost always indicates a
// misconfiguration rather than deliberate intent.
func validateUpstreamTLS(t TLSConfig) error {
	if t.InsecureSkipVerify && (t.CAFile != "" || t.CertFile != "" || t.KeyFile != "") {
		return errors.New("insecure_skip_verify and tls cert/key/ca_file are mutually exclusive; " +
			"custom TLS material is ignored when certificate verification is disabled")
	}
	if (t.CertFile == "") != (t.KeyFile == "") {
		return errors.New("upstream tls.cert_file and tls.key_file must both be set for mTLS")
	}
	return nil
}

// validateMCPTools checks that each MCP tool has a name and an upstream URL.
func validateMCPTools(tools []MCPToolConfig) error {
	for i, t := range tools {
		if t.Name == "" {
			return fmt.Errorf("mcp.tools[%d]: name is required", i)
		}
		if t.UpstreamURL == "" {
			return fmt.Errorf("mcp.tools[%d] (%q): upstream_url is required", i, t.Name)
		}
	}
	return nil
}

// MCPTools converts the config-layer tool definitions to domain.MCPTool values.
// This is the single translation point between config concerns and domain concerns
// for the MCP tool registry.
func (c *Config) MCPTools() []domain.MCPTool {
	tools := make([]domain.MCPTool, len(c.MCP.Tools))
	for i, tc := range c.MCP.Tools {
		tools[i] = domain.MCPTool{
			Name:        tc.Name,
			Tier:        domain.UserTier(tc.Tier),
			RateGroup:   tc.RateGroup,
			Description: tc.Description,
			UpstreamURL: tc.UpstreamURL,
		}
	}
	return tools
}

// ToDomainRoutes converts the config-layer route definitions to domain.Route values.
// This is the single translation point between config concerns and domain concerns.
func (c *Config) ToDomainRoutes() []*domain.Route {
	routes := make([]*domain.Route, 0, len(c.Routes))
	for _, rc := range c.Routes {
		urls, weights := normalizeWeightedURLs(rc.Upstream.URL, rc.Upstream.URLs, rc.Upstream.WeightedURLs)
		if len(urls) == 0 {
			// Defensive guard for callers that bypass Load/validate. Under normal operation
			// validateUpstream already rejects zero-URL upstreams before ToDomainRoutes runs.
			continue
		}
		routes = append(routes, &domain.Route{
			Name: rc.Name,
			Match: domain.MatchCriteria{
				PathPrefix: rc.Match.PathPrefix,
				Methods:    upperMethods(rc.Match.Methods),
				Headers:    rc.Match.Headers,
			},
			Upstream: domain.UpstreamTarget{
				// URL is pre-set to the first pool entry so callers that read URL
				// directly (health checker, proxy fallback) see a valid URL before
				// the load-balancing decorator selects from the pool.
				URL:             urls[0],
				URLs:            urls,
				Weights:         weights,
				StripPrefix:     rc.Upstream.StripPrefix,
				Timeout:         time.Duration(rc.Upstream.TimeoutSecs) * time.Second,
				WebSocket:       rc.Upstream.WebSocket,
				CacheTTL:        time.Duration(rc.Upstream.CacheTTLSecs) * time.Second,
				Retry:           ToRetryConfig(rc.Upstream.Retry),
				HeaderTransform: toHeaderTransform(rc.Upstream.HeaderTransform),
				TLS:             toTLSConfig(rc.Upstream.TLS),
			},
		})
	}
	return routes
}

// upperMethods returns a new slice with every method converted to uppercase.
// HTTP methods are case-sensitive by spec (RFC 7230 §3.1.1); the domain layer
// uses exact comparison, so all methods must be uppercase before storage.
// Returns nil when methods is nil or empty.
func upperMethods(methods []string) []string {
	if len(methods) == 0 {
		return methods
	}
	out := make([]string, len(methods))
	for i, m := range methods {
		out[i] = strings.ToUpper(m)
	}
	return out
}

// normalizeWeightedURLs resolves the upstream URL pool and optional weights from
// the three config fields in priority order: weighted_urls > urls > url.
// Returns a non-empty URL slice and a parallel weights slice (nil when uniform).
func normalizeWeightedURLs(primary string, urls []string, weighted []WeightedURL) ([]string, []int) {
	if len(weighted) > 0 {
		out := make([]string, 0, len(weighted))
		wts := make([]int, 0, len(weighted))
		for _, w := range weighted {
			if w.Weight > 0 {
				out = append(out, w.URL)
				wts = append(wts, w.Weight)
			}
		}
		if len(out) > 0 {
			return out, wts
		}
	}
	if len(urls) > 0 {
		return urls, nil
	}
	return []string{primary}, nil
}

// ToRetryConfig converts a RetryConfig to the equivalent domain.RetryConfig.
// Exported so the container package can reuse it rather than duplicating the mapping.
func ToRetryConfig(r RetryConfig) domain.RetryConfig {
	return domain.RetryConfig{
		Enabled:          r.Enabled,
		MaxAttempts:      r.MaxAttempts,
		InitialBackoffMs: r.InitialBackoffMs,
		Multiplier:       r.Multiplier,
		RetryableStatus:  r.RetryableStatus,
	}
}

func toTLSConfig(t TLSConfig) domain.TLSConfig {
	return domain.TLSConfig{
		CAFile:             t.CAFile,
		CertFile:           t.CertFile,
		KeyFile:            t.KeyFile,
		InsecureSkipVerify: t.InsecureSkipVerify,
	}
}

func toHeaderRules(r HeaderRules) domain.HeaderRules {
	return domain.HeaderRules{Add: r.Add, Set: r.Set, Remove: r.Remove}
}

func toHeaderTransform(ht HeaderTransformConfig) domain.HeaderTransform {
	return domain.HeaderTransform{
		Request:  toHeaderRules(ht.Request),
		Response: toHeaderRules(ht.Response),
	}
}
