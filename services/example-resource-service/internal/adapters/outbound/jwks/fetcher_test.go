package jwks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/jwks"
)

// fakeJWKSServer returns a *httptest.Server serving a JWKS document built
// from the supplied (kid, public key) tuples. The hit counter lets tests
// assert how many times the upstream was contacted.
func fakeJWKSServer(t *testing.T, hits *atomic.Int64, keys ...keyEntry) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.WriteHeader(http.StatusOK)
		body := map[string]any{"keys": []map[string]string{}}
		var out []map[string]string
		for _, k := range keys {
			out = append(out, map[string]string{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": k.kid,
				"n":   base64.RawURLEncoding.EncodeToString(k.pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigEndian(k.pub.E)),
			})
		}
		body["keys"] = out
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type keyEntry struct {
	kid string
	pub *rsa.PublicKey
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func bigEndian(e int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(e))
	return new(big.Int).SetBytes(buf[:]).Bytes()
}

func TestFetcher_KeyByID_InitialFetchSucceeds(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	srv := fakeJWKSServer(t, nil, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewFetcher(srv.URL)

	// Act
	got, err := f.KeyByID(context.Background(), "kid-a")

	// Assert
	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if !got.Equal(&priv.PublicKey) {
		t.Error("returned public key does not match expected")
	}
}

func TestFetcher_KeyByID_CachesAcrossCalls(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	var hits atomic.Int64
	srv := fakeJWKSServer(t, &hits, keyEntry{kid: "kid-cache", pub: &priv.PublicKey})
	f := jwks.NewFetcher(srv.URL)

	// Act — call KeyByID three times in quick succession.
	for i := 0; i < 3; i++ {
		if _, err := f.KeyByID(context.Background(), "kid-cache"); err != nil {
			t.Fatalf("KeyByID #%d: %v", i, err)
		}
	}

	// Assert — exactly one upstream HTTP fetch happened.
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
}

func TestFetcher_KeyByID_RefreshOnUnknownKID(t *testing.T) {
	// Arrange — first response has kid-a; second response has both kid-a and kid-b.
	privA := newRSAKey(t)
	privB := newRSAKey(t)
	var rotation atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rotation.Add(1)
		body := map[string]any{"keys": []map[string]string{}}
		entries := []map[string]string{
			{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "kid-a",
				"n": base64.RawURLEncoding.EncodeToString(privA.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(bigEndian(privA.PublicKey.E))},
		}
		if rotation.Load() >= 2 {
			entries = append(entries, map[string]string{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "kid-b",
				"n": base64.RawURLEncoding.EncodeToString(privB.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(bigEndian(privB.PublicKey.E)),
			})
		}
		body["keys"] = entries
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	// Set refresh rate limit to 0 so the out-of-cycle refresh fires immediately.
	f := jwks.NewFetcher(srv.URL, jwks.WithRefreshRateLimit(0))

	// Act — initial fetch picks up kid-a; second call asks for kid-b, which
	// is not in the cache, triggering a refresh that brings it in.
	if _, err := f.KeyByID(context.Background(), "kid-a"); err != nil {
		t.Fatalf("KeyByID(kid-a): %v", err)
	}
	pub, err := f.KeyByID(context.Background(), "kid-b")

	// Assert
	if err != nil {
		t.Fatalf("KeyByID(kid-b) after refresh: %v", err)
	}
	if !pub.Equal(&privB.PublicKey) {
		t.Error("returned public key does not match privB")
	}
}

func TestFetcher_KeyByID_UnknownKIDAfterRefresh(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	srv := fakeJWKSServer(t, nil, keyEntry{kid: "kid-only", pub: &priv.PublicKey})
	f := jwks.NewFetcher(srv.URL, jwks.WithRefreshRateLimit(0))

	// Act — initial fetch gets kid-only; query for kid-bogus.
	if _, err := f.KeyByID(context.Background(), "kid-only"); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}
	_, err := f.KeyByID(context.Background(), "kid-bogus")

	// Assert — fail-closed semantics: missing kid after refresh is ErrUnknownKID.
	if err == nil {
		t.Fatal("expected error for unknown kid, got nil")
	}
	if !errors.Is(err, jwks.ErrUnknownKID) {
		t.Errorf("error = %v, want ErrUnknownKID", err)
	}
}

func TestFetcher_KeyByID_RateLimitedRefresh(t *testing.T) {
	// Arrange — only kid-a is ever published; rapid queries for kid-missing
	// must not produce more than one extra upstream hit within the rate window.
	priv := newRSAKey(t)
	var hits atomic.Int64
	srv := fakeJWKSServer(t, &hits, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewFetcher(srv.URL, jwks.WithRefreshRateLimit(time.Minute))

	// Seed cache
	if _, err := f.KeyByID(context.Background(), "kid-a"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("baseline hits = %d, want 1", got)
	}

	// Act — five rapid queries for an unknown kid.
	for i := 0; i < 5; i++ {
		_, _ = f.KeyByID(context.Background(), "kid-missing")
	}

	// Assert — at most one extra hit happened (the first miss triggered a refresh;
	// the next four were rate-limited and did not contact upstream).
	if got := hits.Load(); got > 2 {
		t.Errorf("hits = %d after 5 misses, want at most 2 (1 seed + 1 refresh)", got)
	}
}

func TestFetcher_KeyByID_UpstreamErrorFailsClosed(t *testing.T) {
	// Arrange — upstream returns 500 on every call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	f := jwks.NewFetcher(srv.URL)

	// Act
	_, err := f.KeyByID(context.Background(), "kid-any")

	// Assert — error is propagated (validator will map to inactive). No silent
	// nil-key return.
	if err == nil {
		t.Fatal("expected error for upstream 500, got nil")
	}
}

func TestFetcher_KeyByID_ContextCancelled(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	srv := fakeJWKSServer(t, nil, keyEntry{kid: "kid-ctx", pub: &priv.PublicKey})
	f := jwks.NewFetcher(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	// Act
	_, err := f.KeyByID(ctx, "kid-ctx")

	// Assert
	if err == nil {
		t.Fatal("expected error when context cancelled, got nil")
	}
}

func TestFetcher_KeyByID_EmptyKIDRejected(t *testing.T) {
	// Arrange
	f := jwks.NewFetcher("http://example.invalid")

	// Act
	_, err := f.KeyByID(context.Background(), "")

	// Assert
	if err == nil {
		t.Fatal("expected error for empty kid, got nil")
	}
}

func TestNewFetcher_EmptyURL(t *testing.T) {
	// Arrange / Act / Assert
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected NewFetcher(\"\") to panic, got nil")
		}
	}()
	_ = jwks.NewFetcher("")
}

// Silence unused-import lints in case fmt is not needed after refactors.
var _ = fmt.Sprintf
