package domain

import "time"

// RateLimitRule defines the token-bucket parameters for rate limiting.
// The concrete rate.Limiter (stdlib-backed) is created by the adapter layer;
// this struct is a pure data type that lives in the domain so configuration
// and application code can reference it without importing adapter packages.
type RateLimitRule struct {
	RequestsPerSecond float64
	BurstSize         int
}

// WindowRule holds the parameters shared by all window-based rate limiting
// algorithms. Embedding it prevents the three window rule types from silently
// diverging while keeping field access idiomatic (rule.RequestsPerWindow, etc.).
type WindowRule struct {
	RequestsPerWindow int
	WindowDuration    time.Duration
}

// FixedWindowRule defines parameters for the fixed-window counter algorithm.
// Requests are counted in non-overlapping windows of WindowDuration. Once
// RequestsPerWindow is reached, all further requests in that window are denied.
type FixedWindowRule struct{ WindowRule }

// SlidingWindowLogRule defines parameters for the sliding-window log algorithm.
// Every allowed request is timestamped. On each new request, entries older than
// WindowDuration are discarded and the remaining count is compared to the limit.
// Most accurate algorithm; memory cost is O(N requests within the window).
type SlidingWindowLogRule struct{ WindowRule }

// SlidingWindowCounterRule defines parameters for the sliding-window counter
// algorithm. It tracks two consecutive fixed-window counts (current and previous)
// and estimates the in-window count by linear interpolation. O(1) memory.
// Approximation error is empirically < 0.003% (Cloudflare analysis).
type SlidingWindowCounterRule struct{ WindowRule }

// LeakyBucketRule defines parameters for the leaky bucket (reject-only) algorithm.
// New requests are denied immediately when the virtual queue is full.
// The queue drains at DrainRatePerSecond, so the effective throughput is constant.
type LeakyBucketRule struct {
	DrainRatePerSecond float64
	QueueDepth         int
}

// ConcurrencyRule defines parameters for the concurrency limiter.
// Unlike rate-based algorithms, this counts simultaneous in-flight requests
// rather than requests per unit time. Slots are reserved with Acquire and
// freed with Release; requests are denied when all slots are taken.
type ConcurrencyRule struct {
	MaxInFlight int
}
