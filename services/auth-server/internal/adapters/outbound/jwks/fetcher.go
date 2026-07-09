// Package jwks implements ports.ClientJWKSFetcher (RFC 7523 / ADR-0023) by
// fetching each client's registered jwks_uri over HTTP. Unlike
// example-resource-service's single-URL jwks.Fetcher (this platform's own
// signing keys, fixed at process startup), PerClientFetcher caches one key
// set per URI, since every calling client may register a different
// endpoint.
//
// Failure semantics are fail-closed: any error from the upstream —
// network failure, non-200 response, malformed JWKS, unknown kid — is
// returned to the caller. The fetcher never silently returns a nil key.
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

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Compile-time interface check — fails to build if the adapter drifts
// from the port.
var _ ports.ClientJWKSFetcher = (*PerClientFetcher)(nil)

// ErrUnknownKID is returned by FetchKey when the requested kid is not
// present in the JWKS document at the given URI.
var ErrUnknownKID = errors.New("unknown kid")

// defaultCacheTTL matches example-resource-service's jwks.Fetcher default.
// No per-URI rate limit on out-of-cycle refresh is applied here (unlike
// that fetcher) — see ADR-0023's Negative consequences: a production
// deployment fronting untrusted registrants should add one before a
// misbehaving client_id could be used to hammer an arbitrary jwks_uri via
// repeated cache-miss lookups.
const defaultCacheTTL = time.Hour

// keySet is the cached state for one jwks_uri.
type keySet struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

// PerClientFetcher resolves (jwksURI, kid) -> *rsa.PublicKey, caching one
// key set per URI. Safe for concurrent use.
type PerClientFetcher struct {
	client   *http.Client
	cacheTTL time.Duration

	mu      sync.Mutex
	entries map[string]*keySet // jwksURI -> keySet
}

// NewPerClientFetcher constructs a fetcher using httpClient for upstream
// requests.
func NewPerClientFetcher(httpClient *http.Client) *PerClientFetcher {
	return &PerClientFetcher{
		client:   httpClient,
		cacheTTL: defaultCacheTTL,
		entries:  make(map[string]*keySet),
	}
}

// FetchKey returns the RSA public key identified by kid at jwksURI,
// fetching and caching the document on a cache miss or TTL expiry.
func (f *PerClientFetcher) FetchKey(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
	ks := f.entryFor(jwksURI)
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if pub, ok := ks.keys[kid]; ok && time.Since(ks.lastFetch) <= f.cacheTTL {
		return pub, nil
	}
	doc, err := f.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	ks.keys = decodeKeySet(doc.Keys)
	ks.lastFetch = time.Now()
	pub, ok := ks.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
	}
	return pub, nil
}

// entryFor returns the keySet for jwksURI, creating one on first use.
func (f *PerClientFetcher) entryFor(jwksURI string) *keySet {
	f.mu.Lock()
	defer f.mu.Unlock()
	ks, ok := f.entries[jwksURI]
	if !ok {
		ks = &keySet{keys: map[string]*rsa.PublicKey{}}
		f.entries[jwksURI] = ks
	}
	return ks
}

func (f *PerClientFetcher) fetchJWKS(ctx context.Context, jwksURI string) (jwksDoc, error) {
	var doc jwksDoc
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return doc, fmt.Errorf("jwks: build request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return doc, fmt.Errorf("jwks: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return doc, fmt.Errorf("jwks: upstream status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("jwks: decode: %w", err)
	}
	return doc, nil
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// decodeKeySet converts the wire-format JWK list into a kid -> public-key
// map. One bad key does not invalidate the set; bad keys are skipped
// silently.
func decodeKeySet(keys []jwk) map[string]*rsa.PublicKey {
	next := make(map[string]*rsa.PublicKey, len(keys))
	for _, k := range keys {
		pub, err := decodeRSAJWK(k)
		if err != nil {
			continue
		}
		next[k.Kid] = pub
	}
	return next
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
