package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/jedi-knights/go-platform/jwtutil"

	jwtadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/jwt"
)

// staticSource adapts a fixed (kid, *rsa.PublicKey) pair to the KeySource shape.
func staticSource(t *testing.T, expectedKID string, pub *rsa.PublicKey) jwtutil.KeySource {
	t.Helper()
	return func(_ context.Context, kid string) (*rsa.PublicKey, error) {
		if kid != expectedKID {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	}
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func signedAccessToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwtutil.ClaimsConfig) string {
	t.Helper()
	c := jwtutil.NewClaims(claims)
	raw, err := jwtutil.SignRS256(c, priv, kid)
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}
	return raw
}

func TestRS256Validator_Validate_ActiveOnValidToken(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	source := staticSource(t, "kid-v1", &priv.PublicKey)
	v := jwtadapter.NewRS256Validator(source, "")
	raw := signedAccessToken(t, priv, "kid-v1", jwtutil.ClaimsConfig{
		Issuer:    "test-issuer",
		Subject:   "user-1",
		TokenID:   "tok-1",
		ClientID:  "client-a",
		Scope:     "read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Act
	got, err := v.Validate(context.Background(), raw)

	// Assert
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", got.Subject, "user-1")
	}
}

func TestRS256Validator_Validate_InactiveOnExpiredToken(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	source := staticSource(t, "kid-v1", &priv.PublicKey)
	v := jwtadapter.NewRS256Validator(source, "")
	past := time.Now().Add(-2 * time.Hour)
	raw := signedAccessToken(t, priv, "kid-v1", jwtutil.ClaimsConfig{
		Issuer:    "test-issuer",
		Subject:   "user-exp",
		TokenID:   "tok-exp",
		ClientID:  "client-a",
		Scope:     "read",
		IssuedAt:  past,
		ExpiresAt: past.Add(time.Hour),
	})

	// Act — RFC 7662 §2.2: an expired token is inactive, not an error.
	got, err := v.Validate(context.Background(), raw)

	// Assert
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Active {
		t.Error("Active = true, want false for expired token")
	}
}

func TestRS256Validator_Validate_InactiveOnWrongSigner(t *testing.T) {
	// Arrange — issue with one key, validate via a source backed by a different key.
	signingKey := newRSAKey(t)
	differentKey := newRSAKey(t)
	source := staticSource(t, "kid-v1", &differentKey.PublicKey)
	v := jwtadapter.NewRS256Validator(source, "")
	raw := signedAccessToken(t, signingKey, "kid-v1", jwtutil.ClaimsConfig{
		Issuer:    "test-issuer",
		Subject:   "user-1",
		TokenID:   "tok-1",
		ClientID:  "client-a",
		Scope:     "read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Act
	got, err := v.Validate(context.Background(), raw)

	// Assert — RFC 7662: signature failure is inactive, not error.
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Active {
		t.Error("Active = true, want false for wrong-signer token")
	}
}

func TestRS256Validator_Validate_InactiveOnHS256Token(t *testing.T) {
	// Arrange — algorithm-confusion defence (RFC 8725 §3.1).
	priv := newRSAKey(t)
	source := staticSource(t, "kid-v1", &priv.PublicKey)
	v := jwtadapter.NewRS256Validator(source, "")
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["typ"] = "at+jwt"
	token.Header["kid"] = "kid-v1"
	raw, err := token.SignedString([]byte("32-byte-hmac-secret-for-attack!!!"))
	if err != nil {
		t.Fatalf("constructing HS256 token: %v", err)
	}

	// Act
	got, err := v.Validate(context.Background(), raw)

	// Assert
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Active {
		t.Error("RS256 validator accepted HS256-signed token; algorithm-confusion defence broken")
	}
}

func TestRS256Validator_Validate_VerifiesIssuerWhenSet(t *testing.T) {
	// Arrange
	priv := newRSAKey(t)
	source := staticSource(t, "kid-v1", &priv.PublicKey)
	v := jwtadapter.NewRS256Validator(source, "expected-issuer")
	raw := signedAccessToken(t, priv, "kid-v1", jwtutil.ClaimsConfig{
		Issuer:    "wrong-issuer",
		Subject:   "user-iss",
		TokenID:   "tok-iss",
		ClientID:  "client-a",
		Scope:     "read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Act
	got, err := v.Validate(context.Background(), raw)

	// Assert
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Active {
		t.Error("validator accepted token with mismatched iss")
	}
}

func TestNewRS256Validator_NilKeySource(t *testing.T) {
	// Arrange / Act / Assert
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected NewRS256Validator(nil, ...) to panic, got nil")
		}
	}()
	_ = jwtadapter.NewRS256Validator(nil, "")
}
