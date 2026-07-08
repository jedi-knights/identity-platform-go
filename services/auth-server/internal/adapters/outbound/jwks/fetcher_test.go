package jwks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/jwks"
)

type keyEntry struct {
	kid string
	pub *rsa.PublicKey
}

func fakeJWKSServer(t *testing.T, hits *atomic.Int64, keys ...keyEntry) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
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
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func bigEndian(e int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(e))
	return new(big.Int).SetBytes(buf[:]).Bytes()
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func TestPerClientFetcher_FetchKey_Success(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	srv := fakeJWKSServer(t, nil, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewPerClientFetcher(http.DefaultClient)

	// Act
	got, err := f.FetchKey(context.Background(), srv.URL, "kid-a")

	// Assert
	if err != nil {
		t.Fatalf("FetchKey: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 || got.E != priv.E {
		t.Error("returned key does not match the served key")
	}
}

func TestPerClientFetcher_FetchKey_UnknownKid(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	srv := fakeJWKSServer(t, nil, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewPerClientFetcher(http.DefaultClient)

	// Act
	_, err := f.FetchKey(context.Background(), srv.URL, "kid-does-not-exist")

	// Assert
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestPerClientFetcher_FetchKey_DifferentURIsAreIndependent(t *testing.T) {
	// Arrange — two clients, two distinct JWKS endpoints, two distinct keys.
	privA := newRSAKey(t)
	privB := newRSAKey(t)
	srvA := fakeJWKSServer(t, nil, keyEntry{kid: "kid-shared", pub: &privA.PublicKey})
	srvB := fakeJWKSServer(t, nil, keyEntry{kid: "kid-shared", pub: &privB.PublicKey})
	f := jwks.NewPerClientFetcher(http.DefaultClient)

	// Act
	gotA, errA := f.FetchKey(context.Background(), srvA.URL, "kid-shared")
	gotB, errB := f.FetchKey(context.Background(), srvB.URL, "kid-shared")

	// Assert
	if errA != nil || errB != nil {
		t.Fatalf("FetchKey errors: %v, %v", errA, errB)
	}
	if gotA.N.Cmp(privA.N) != 0 {
		t.Error("srvA lookup returned the wrong key")
	}
	if gotB.N.Cmp(privB.N) != 0 {
		t.Error("srvB lookup returned the wrong key")
	}
}

func TestPerClientFetcher_FetchKey_CachesWithinTTL(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	var hits atomic.Int64
	srv := fakeJWKSServer(t, &hits, keyEntry{kid: "kid-a", pub: &priv.PublicKey})
	f := jwks.NewPerClientFetcher(http.DefaultClient)

	// Act
	if _, err := f.FetchKey(context.Background(), srv.URL, "kid-a"); err != nil {
		t.Fatalf("first FetchKey: %v", err)
	}
	if _, err := f.FetchKey(context.Background(), srv.URL, "kid-a"); err != nil {
		t.Fatalf("second FetchKey: %v", err)
	}

	// Assert
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hit %d times, want exactly 1 (second call should be cached)", got)
	}
}

func TestPerClientFetcher_FetchKey_UpstreamError(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	f := jwks.NewPerClientFetcher(http.DefaultClient)

	// Act
	_, err := f.FetchKey(context.Background(), srv.URL, "kid-a")

	// Assert
	if err == nil {
		t.Fatal("expected error for upstream failure")
	}
}
