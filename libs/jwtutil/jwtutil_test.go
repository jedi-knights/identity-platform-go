package jwtutil_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
)

var testKey = []byte("a-test-signing-key-that-is-32-chars-long!!")

func signedToken(t *testing.T, claims *jwtutil.Claims) string {
	t.Helper()
	raw, err := jwtutil.Sign(claims, testKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return raw
}

// assertField fails the test if got != want, reporting label and both values.
func assertField(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", label, got, want)
	}
}

// assertStringSliceEqual compares two string slices element-by-element,
// failing the test with a clear message on length or value mismatch.
func assertStringSliceEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d elements, want %d", label, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d]: got %q, want %q", label, i, got[i], want[i])
		}
	}
}

func TestRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "identity-platform",
		Subject:   "client-abc",
		TokenID:   "token-id-1",
		ClientID:  "client-abc",
		Scope:     "read write",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})

	raw := signedToken(t, claims)

	got, err := jwtutil.Parse(raw, testKey)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	assertField(t, "Subject", got.Subject, "client-abc")
	assertField(t, "ClientID", got.ClientID, "client-abc")
	assertField(t, "Scope", got.Scope, "read write")
	assertField(t, "Issuer", got.Issuer, "identity-platform")
	assertField(t, "ID", got.ID, "token-id-1")

	// jwt.NumericDate embeds time.Time — use the promoted Equal method directly.
	if !got.IssuedAt.Equal(now) {
		t.Errorf("IssuedAt: got %v, want %v", got.IssuedAt, now)
	}
	if !got.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, now.Add(time.Hour))
	}
}

func TestParse_ExpiredToken(t *testing.T) {
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "identity-platform",
		Subject:   "sub",
		TokenID:   "id",
		ClientID:  "client",
		Scope:     "read",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	raw := signedToken(t, claims)

	_, err := jwtutil.Parse(raw, testKey)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !errors.Is(err, jwtutil.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestParse_WrongKey(t *testing.T) {
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "identity-platform",
		Subject:   "sub",
		TokenID:   "id",
		ClientID:  "client",
		Scope:     "read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	raw := signedToken(t, claims)

	wrongKey := []byte("wrong-key-that-is-also-32-chars!!")
	_, err := jwtutil.Parse(raw, wrongKey)
	if err == nil {
		t.Fatal("expected error for wrong signing key, got nil")
	}
	if !errors.Is(err, jwtutil.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestParse_MalformedToken(t *testing.T) {
	_, err := jwtutil.Parse("not.a.jwt", testKey)
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
	if !errors.Is(err, jwtutil.ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got %v", err)
	}
}

// TestParse_NoneAlgorithmRejected verifies the algorithm-confusion guard in
// the jwt.Keyfunc: a token using the "none" signing method must be rejected
// regardless of the signing key supplied. This is the test that was previously
// absent, leaving the guard unverified.
func TestParse_NoneAlgorithmRejected(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, &jwtutil.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "sub",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("constructing none-alg token: %v", err)
	}
	_, err = jwtutil.Parse(raw, testKey)
	if err == nil {
		t.Fatal("expected error for none-algorithm token, got nil")
	}
}

func TestSign_NilClaims(t *testing.T) {
	_, err := jwtutil.Sign(nil, testKey)
	if err == nil {
		t.Fatal("expected error for nil claims, got nil")
	}
}

func TestSign_EmptyKey(t *testing.T) {
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "identity-platform",
		Subject:   "sub",
		TokenID:   "id",
		ClientID:  "client",
		Scope:     "read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_, err := jwtutil.Sign(claims, []byte{})
	if err == nil {
		t.Fatal("expected error for empty signing key, got nil")
	}
}

func TestParse_EmptyKey(t *testing.T) {
	_, err := jwtutil.Parse("any.token.value", []byte{})
	if err == nil {
		t.Fatal("expected error for empty signing key, got nil")
	}
}

func TestRoundTrip_RolesAndPermissionsAbsentWhenNil(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "identity-platform",
		Subject:   "client-abc",
		TokenID:   "token-id-2",
		ClientID:  "client-abc",
		Scope:     "read",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})

	raw := signedToken(t, claims)

	got, err := jwtutil.Parse(raw, testKey)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Roles) != 0 {
		t.Errorf("Roles: expected empty/nil, got %v", got.Roles)
	}
	if len(got.Permissions) != 0 {
		t.Errorf("Permissions: expected empty/nil, got %v", got.Permissions)
	}
}

func TestRoundTrip_RolesAndPermissionsRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	roles := []string{"admin", "editor"}
	permissions := []string{"articles:read", "articles:write", "users:read"}

	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:      "identity-platform",
		Subject:     "user-xyz",
		TokenID:     "token-id-3",
		ClientID:    "client-abc",
		Scope:       "read write",
		Roles:       roles,
		Permissions: permissions,
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Hour),
	})

	raw := signedToken(t, claims)

	got, err := jwtutil.Parse(raw, testKey)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	assertStringSliceEqual(t, "Roles", got.Roles, roles)
	assertStringSliceEqual(t, "Permissions", got.Permissions, permissions)
}
