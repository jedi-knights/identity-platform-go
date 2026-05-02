package ports

import (
	"net/http"
	"time"
)

// CacheEntry is a captured HTTP response stored in the response cache.
// The Body slice is a full copy of the response body and is safe to retain indefinitely.
type CacheEntry struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// ResponseCache is the outbound port for storing and retrieving cached HTTP responses.
// Implementations must be safe for concurrent use.
//
// Get returns the entry and true on a cache hit, or nil and false on a miss or expiry.
// Set stores entry under key with the given TTL; a zero or negative TTL is implementation-defined.
type ResponseCache interface {
	Get(key string) (*CacheEntry, bool)
	Set(key string, entry *CacheEntry, ttl time.Duration)
}

// CacheTTLKey is the request-context key used to communicate the per-route cache TTL
// from proxy.Transport (where the route is resolved) back to CacheMiddleware.
type CacheTTLKey struct{}

// CacheTTLHolder is a mutable TTL hint injected into the request context by
// CacheMiddleware. proxy.Transport populates the TTL field after resolving the
// route so that CacheMiddleware can honour per-route TTL overrides without a
// direct dependency between inbound and outbound adapter packages.
//
// The zero-value TTL means the holder was not populated; CacheMiddleware falls
// back to the global default in that case.
type CacheTTLHolder struct {
	TTL time.Duration
}
