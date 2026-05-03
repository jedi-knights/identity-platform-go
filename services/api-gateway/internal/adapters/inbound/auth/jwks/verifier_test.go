//go:build unit

package jwks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/auth/jwks"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
)

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// jwksHandlerFor builds an HTTP handler that serves a JWKS containing the public
// key for the given private key. The key ID "test-key" is stable across calls.
func jwksHandlerFor(key *rsa.PrivateKey) http.HandlerFunc {
	pub := &key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	body, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": n, "e": e},
		},
	})
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// newJWKSVerifier starts a test JWKS server for key and returns a verifier backed
// by it. The server and the refresh context are cleaned up via t.Cleanup.
func newJWKSVerifier(t *testing.T, key *rsa.PrivateKey) *jwks.Verifier {
	t.Helper()
	srv := httptest.NewServer(jwksHandlerFor(key))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	v, err := jwks.New(ctx, config.AuthConfig{JWKSURL: srv.URL})
	if err != nil {
		t.Fatalf("jwks.New: %v", err)
	}
	return v
}

// signRS256Token signs a jwtutil.Claims JWT with RS256. The kid header is set to
// "test-key" to match the key ID served by jwksHandlerFor.
func signRS256Token(t *testing.T, key *rsa.PrivateKey, subject string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Subject:   subject,
		TokenID:   "tid",
		ClientID:  subject,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign rs256: %v", err)
	}
	return raw
}

func TestJWKS_New_EmptyURL_ReturnsError(t *testing.T) {
	_, err := jwks.New(context.Background(), config.AuthConfig{JWKSURL: ""})
	if err == nil {
		t.Fatal("expected error for empty JWKSURL, got nil")
	}
}

func TestJWKS_ValidToken_ReturnsClaims(t *testing.T) {
	key := newRSAKey(t)
	v := newJWKSVerifier(t, key)
	raw := signRS256Token(t, key, "alice", time.Minute)

	claims, err := v.Verify(raw)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "alice")
	}
}

func TestJWKS_ExpiredToken_ReturnsTokenExpired(t *testing.T) {
	key := newRSAKey(t)
	v := newJWKSVerifier(t, key)
	raw := signRS256Token(t, key, "alice", -time.Second)

	_, err := v.Verify(raw)

	if !errors.Is(err, jwtutil.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got: %v", err)
	}
}

// TestJWKS_WrongKey_ReturnsTokenInvalid signs a token with a key whose public
// counterpart is NOT in the JWKS, so signature verification must fail.
func TestJWKS_WrongKey_ReturnsTokenInvalid(t *testing.T) {
	key := newRSAKey(t)
	wrongKey := newRSAKey(t) // different key; JWKS only contains key's public key
	v := newJWKSVerifier(t, key)
	raw := signRS256Token(t, wrongKey, "alice", time.Minute)

	_, err := v.Verify(raw)

	if !errors.Is(err, jwtutil.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got: %v", err)
	}
}

func TestJWKS_MalformedToken_ReturnsTokenMalformed(t *testing.T) {
	key := newRSAKey(t)
	v := newJWKSVerifier(t, key)

	_, err := v.Verify("not.a.jwt")

	if !errors.Is(err, jwtutil.ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got: %v", err)
	}
}
