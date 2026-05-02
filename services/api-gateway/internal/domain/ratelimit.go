package domain

// RateLimitRule defines the token-bucket parameters for rate limiting.
// The concrete rate.Limiter (stdlib-backed) is created by the adapter layer;
// this struct is a pure data type that lives in the domain so configuration
// and application code can reference it without importing adapter packages.
type RateLimitRule struct {
	RequestsPerSecond float64
	BurstSize         int
}
