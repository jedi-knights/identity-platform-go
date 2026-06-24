//go:build unit

package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/jedi-knights/go-platform/jwtutil"
	"github.com/jedi-knights/go-platform/testutil"
)

// rs256TestKey returns a fresh 2048-bit RSA keypair for one test.
func rs256TestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

// staticRS256KeySource returns a KeySource that resolves exactly one kid.
func staticRS256KeySource(t *testing.T, kid string, pub *rsa.PublicKey) jwtutil.KeySource {
	t.Helper()
	return func(_ context.Context, requested string) (*rsa.PublicKey, error) {
		if requested != kid {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	}
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, cfg jwtutil.ClaimsConfig) string {
	t.Helper()
	raw, err := jwtutil.SignRS256(jwtutil.NewClaims(cfg), priv, kid)
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	return raw
}

func TestRS256AuthMiddleware_ValidToken_CallsNext(t *testing.T) {
	// Arrange
	priv := rs256TestKey(t)
	source := staticRS256KeySource(t, "kid-rs", &priv.PublicKey)
	raw := signRS256(t, priv, "kid-rs", jwtutil.ClaimsConfig{
		Subject:   "user-1",
		Scope:     "read",
		ClientID:  "client-a",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	called := false
	mw := RS256AuthMiddleware(source, "", "", testutil.NewTestLogger())

	// Act
	w := httptest.NewRecorder()
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if !called {
		t.Fatal("next handler not called")
	}
	if got := w.Code; got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
}

func TestRS256AuthMiddleware_ExpiredToken_Returns401(t *testing.T) {
	// Arrange
	priv := rs256TestKey(t)
	source := staticRS256KeySource(t, "kid-rs", &priv.PublicKey)
	past := time.Now().Add(-2 * time.Hour)
	raw := signRS256(t, priv, "kid-rs", jwtutil.ClaimsConfig{
		Subject:   "user-1",
		Scope:     "read",
		IssuedAt:  past,
		ExpiresAt: past.Add(time.Hour),
	})
	mw := RS256AuthMiddleware(source, "", "", testutil.NewTestLogger())

	// Act
	w := httptest.NewRecorder()
	called := false
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if called {
		t.Error("next handler called for expired token")
	}
	if got := w.Code; got != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", got)
	}
}

func TestRS256AuthMiddleware_HS256Token_Rejected(t *testing.T) {
	// Arrange — algorithm-confusion defence (RFC 8725 §3.1).
	priv := rs256TestKey(t)
	source := staticRS256KeySource(t, "kid-rs", &priv.PublicKey)
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["typ"] = "at+jwt"
	token.Header["kid"] = "kid-rs"
	raw, err := token.SignedString([]byte("32-byte-hmac-secret-for-attack!!"))
	if err != nil {
		t.Fatalf("constructing HS256 token: %v", err)
	}
	mw := RS256AuthMiddleware(source, "", "", testutil.NewTestLogger())

	// Act
	w := httptest.NewRecorder()
	called := false
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if called {
		t.Error("RS256 middleware accepted HS256-signed token; algorithm-confusion defence broken")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRS256AuthMiddleware_WrongAudience_Returns401(t *testing.T) {
	// Arrange
	priv := rs256TestKey(t)
	source := staticRS256KeySource(t, "kid-rs", &priv.PublicKey)
	raw := signRS256(t, priv, "kid-rs", jwtutil.ClaimsConfig{
		Subject:   "user-1",
		Audience:  []string{"other-service"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	mw := RS256AuthMiddleware(source, "this-service", "", testutil.NewTestLogger())

	// Act
	w := httptest.NewRecorder()
	called := false
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if called {
		t.Error("next handler called for audience-mismatched token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRS256AuthMiddleware_WrongIssuer_Returns401(t *testing.T) {
	// Arrange
	priv := rs256TestKey(t)
	source := staticRS256KeySource(t, "kid-rs", &priv.PublicKey)
	raw := signRS256(t, priv, "kid-rs", jwtutil.ClaimsConfig{
		Subject:   "user-1",
		Issuer:    "wrong-issuer",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	mw := RS256AuthMiddleware(source, "", "expected-issuer", testutil.NewTestLogger())

	// Act
	w := httptest.NewRecorder()
	called := false
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if called {
		t.Error("next handler called for wrong-issuer token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRS256AuthMiddleware_NoBearerHeader_Returns401(t *testing.T) {
	// Arrange
	priv := rs256TestKey(t)
	source := staticRS256KeySource(t, "kid-rs", &priv.PublicKey)
	mw := RS256AuthMiddleware(source, "", "", testutil.NewTestLogger())
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)

	// Act
	w := httptest.NewRecorder()
	called := false
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if called {
		t.Error("next handler called without Authorization header")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
