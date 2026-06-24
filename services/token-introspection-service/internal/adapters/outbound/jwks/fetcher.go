// Package jwks implements an HTTP-backed JWKS key source for verifying
// RS256-signed access tokens. The fetcher caches the entire key set in
// memory, refreshes on TTL expiry, and performs a single out-of-cycle
// refresh on cache miss (subject to a configurable rate limit) so a freshly
// rotated key becomes available without waiting for the TTL.
//
// Failure semantics are fail-closed: any error from the upstream — network
// failure, non-200 response, malformed JWKS — is returned to the caller so
// the validator can map it to RFC 7662 `{active: false}`. The fetcher never
// silently returns a nil public key.
package jwks

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// ErrUnknownKID is returned by KeyByID when the requested kid is not present
// in the JWKS document — neither in the in-memory cache nor in the freshly
// refreshed set.
var ErrUnknownKID = errors.New("unknown kid")

// Fetcher resolves kid → *rsa.PublicKey by fetching JWKS over HTTP.
// Safe for concurrent use.
type Fetcher struct {
	url       string
	client    *http.Client
	cacheTTL  time.Duration
	rateLimit time.Duration

	mu             sync.Mutex
	keys           map[string]*rsa.PublicKey
	lastFetch      time.Time
	lastForcedRefr time.Time
}

// Option mutates a Fetcher at construction time.
type Option func(*Fetcher)

// WithHTTPClient overrides the default HTTP client (5s timeout).
func WithHTTPClient(c *http.Client) Option {
	return func(f *Fetcher) { f.client = c }
}

// WithCacheTTL sets how long a successful fetch is reused before the next
// scheduled refresh. Default: 1 hour.
func WithCacheTTL(d time.Duration) Option {
	return func(f *Fetcher) { f.cacheTTL = d }
}

// WithRefreshRateLimit caps how often a cache miss can trigger an
// out-of-cycle refresh. Default: 30 seconds. Zero disables the limit
// (useful in tests).
func WithRefreshRateLimit(d time.Duration) Option {
	return func(f *Fetcher) { f.rateLimit = d }
}

// NewFetcher constructs a Fetcher pointed at the supplied JWKS URL.
// Panics on empty URL — that is a wiring error, not a runtime condition.
func NewFetcher(url string, opts ...Option) *Fetcher {
	if url == "" {
		panic("jwks.NewFetcher: url must not be empty")
	}
	f := &Fetcher{
		url:       url,
		client:    &http.Client{Timeout: 5 * time.Second},
		cacheTTL:  time.Hour,
		rateLimit: 30 * time.Second,
		keys:      map[string]*rsa.PublicKey{},
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// KeyByID returns the RSA public key for the given kid, consulting the cache
// first. On a cache miss, performs an out-of-cycle refresh subject to the
// configured rate limit, then returns either the resolved key or ErrUnknownKID.
func (f *Fetcher) KeyByID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("jwks: kid must not be empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("jwks: context: %w", err)
	}

	f.mu.Lock()
	cached, ok := f.keys[kid]
	stale := time.Since(f.lastFetch) > f.cacheTTL
	canForceRefresh := f.rateLimit == 0 || time.Since(f.lastForcedRefr) >= f.rateLimit
	f.mu.Unlock()

	if ok && !stale {
		return cached, nil
	}

	// Either no entry, or entry is past TTL → fetch.
	switch {
	case !ok && !canForceRefresh:
		// Cache miss but rate-limited. Surface as unknown kid; the validator
		// maps that to inactive. Future requests after the rate window will
		// succeed.
		return nil, fmt.Errorf("%w: %s (refresh rate-limited)", ErrUnknownKID, kid)
	case !ok:
		// Cache miss — perform an out-of-cycle (forced) refresh.
		if err := f.refresh(ctx, true); err != nil {
			return nil, err
		}
	default:
		// Stale cache (or empty after first call) — refresh on schedule.
		if err := f.refresh(ctx, false); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if pub, ok := f.keys[kid]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
}

// refresh fetches the JWKS document and replaces the in-memory cache.
// Holds the mutex during the upstream call to serialise concurrent
// refreshers — a small cost vs the alternative complexity of an in-flight
// promise.
func (f *Fetcher) refresh(ctx context.Context, forced bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if forced {
		f.lastForcedRefr = time.Now()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return fmt.Errorf("jwks: build request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: upstream status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}

	next := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := decodeRSAJWK(k)
		if err != nil {
			// One bad key does not invalidate the set; skip it.
			continue
		}
		next[k.Kid] = pub
	}
	f.keys = next
	f.lastFetch = time.Now()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func decodeRSAJWK(k jwk) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("kty %q is not RSA", k.Kty)
	}
	if k.Alg != "" && k.Alg != "RS256" {
		return nil, fmt.Errorf("alg %q is not RS256", k.Alg)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("exponent does not fit in int64")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
