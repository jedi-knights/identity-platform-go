package domain

import (
	"strings"
	"time"
)

// TLSConfig holds per-upstream mTLS settings.
// A zero-value TLSConfig means no custom TLS — the default shared http.Client is used.
// InsecureSkipVerify=true is an operator opt-in for environments where certificate
// verification is intentionally disabled (e.g., internal meshes with self-signed certs).
type TLSConfig struct {
	// CAFile is the path to a PEM-encoded CA certificate used to verify the upstream's
	// certificate. Empty means the system certificate pool is used.
	CAFile string

	// CertFile and KeyFile are paths to the PEM-encoded client certificate and private
	// key for mutual TLS. Both must be set together; either alone is a misconfiguration.
	CertFile string
	KeyFile  string

	// InsecureSkipVerify disables upstream certificate verification.
	// Never set this in production; it is provided for local development only.
	InsecureSkipVerify bool
}

// IsZero reports whether this TLSConfig carries no custom settings.
// A zero TLSConfig uses the shared default http.Client.
func (t TLSConfig) IsZero() bool {
	return t.CAFile == "" && t.CertFile == "" && t.KeyFile == "" && !t.InsecureSkipVerify
}

// Route represents a single routing rule that maps an inbound request pattern to an upstream target.
// Routes are pure domain types — they carry no HTTP framework dependency.
type Route struct {
	Name     string
	Match    MatchCriteria
	Upstream UpstreamTarget
}

// MatchCriteria defines the conditions an inbound request must satisfy for a route to apply.
// All specified criteria must match; unset fields are treated as wildcards.
type MatchCriteria struct {
	// PathPrefix is the required URL path prefix (e.g. "/api/users").
	// An empty value matches any path.
	PathPrefix string

	// Methods is the list of allowed HTTP methods (e.g. ["GET", "POST"]).
	// An empty slice allows any method. Methods must be uppercase — callers are
	// responsible for normalizing at construction time (e.g. via config.ToDomainRoutes).
	// Incoming request methods from Go's net/http are always uppercase, so exact
	// comparison with == is used instead of case-insensitive EqualFold.
	Methods []string

	// Headers is a map of header name → required value.
	// Every entry must be present and matching for the route to apply.
	// An empty map imposes no header constraints.
	Headers map[string]string
}

// RetryConfig holds the resolved retry policy for an upstream route.
// A zero-value RetryConfig (Enabled=false) means no retry is applied.
//
// MaxAttempts includes the initial attempt: MaxAttempts=3 means one try plus
// two retries. RetryableStatus lists HTTP status codes that are considered
// transient failures and should trigger a retry.
type RetryConfig struct {
	Enabled          bool
	MaxAttempts      int
	InitialBackoffMs int
	Multiplier       float64
	RetryableStatus  []int
}

// HeaderRules is a set of header manipulation operations applied in order:
// Remove first (delete headers entirely), then Set (overwrite or create),
// then Add (write only if the header is not already present).
type HeaderRules struct {
	Add    map[string]string // write if absent
	Set    map[string]string // always overwrite
	Remove []string          // delete entirely
}

// HeaderTransform groups request and response header manipulation rules for a route.
// Zero value means no transformation is applied on either direction.
type HeaderTransform struct {
	Request  HeaderRules
	Response HeaderRules
}

// UpstreamTarget is the destination to which a matched request is forwarded.
type UpstreamTarget struct {
	// URL is the currently-selected upstream URL for this request.
	// When load balancing is active the transport fills this field with the
	// selected entry from URLs before passing the route to the proxy.
	// When load balancing is inactive it holds the single configured URL.
	URL string

	// URLs is the full pool of upstream endpoints for load balancing.
	// Populated by config.ToDomainRoutes: single-URL routes produce a 1-element
	// slice so all transports always see a non-empty pool.
	URLs []string

	// Weights is the relative weight for each entry in URLs (parallel slice).
	// Non-nil only for routes configured with weighted_urls. Nil or empty means
	// all URLs have equal weight and round-robin / uniform selection is used.
	Weights []int

	// StripPrefix is an optional path prefix to remove before forwarding.
	// For example, if StripPrefix is "/api/users" and the request path is
	// "/api/users/123", the upstream receives "/123".
	StripPrefix string

	// Timeout is the per-request deadline for this upstream.
	// Zero means no per-route timeout; the global HTTP client timeout applies instead.
	Timeout time.Duration

	// WebSocket enables streaming / upgrade support for this upstream.
	// When true, the reverse proxy sets FlushInterval to -1 so that response
	// bytes are flushed immediately rather than buffered, which is required for
	// HTTP/1.1 upgrade handshakes (WebSocket, SSE, gRPC-web).
	WebSocket bool

	// CacheTTL is the per-route response cache TTL.
	// Zero means no per-route override; CacheMiddleware uses the global default TTL.
	CacheTTL time.Duration

	// Retry holds the resolved retry policy for this route.
	// When Retry.MaxAttempts > 0 it overrides the global retry config in the transport.
	// A zero-value Retry means use the global config.
	Retry RetryConfig

	// HeaderTransform holds request and response header manipulation rules.
	// Applied by the proxy transport: request rules before forwarding,
	// response rules before returning to the client.
	HeaderTransform HeaderTransform

	// TLS holds the per-upstream mTLS configuration.
	// A zero-value TLS uses the shared default http.Client (no custom TLS).
	TLS TLSConfig
}

// Matches reports whether the given method, path, and headers satisfy this route's
// match criteria. All three dimensions are evaluated; the request must pass all of them.
//
// This is pure domain logic — callers extract these values from *http.Request.
// The domain itself carries no net/http dependency.
func (r *Route) Matches(method, path string, headers map[string]string) bool {
	return r.matchesMethod(method) && r.matchesPath(path) && r.matchesHeaders(headers)
}

func (r *Route) matchesMethod(method string) bool {
	if len(r.Match.Methods) == 0 {
		return true
	}
	for _, m := range r.Match.Methods {
		if m == method {
			return true
		}
	}
	return false
}

func (r *Route) matchesPath(path string) bool {
	if r.Match.PathPrefix == "" {
		return true
	}
	return strings.HasPrefix(path, r.Match.PathPrefix)
}

func (r *Route) matchesHeaders(headers map[string]string) bool {
	for k, v := range r.Match.Headers {
		if headers[k] != v {
			return false
		}
	}
	return true
}
