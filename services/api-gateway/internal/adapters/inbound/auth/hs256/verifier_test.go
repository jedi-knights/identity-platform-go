//go:build unit

package hs256_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/auth/hs256"
)

var testKey = []byte("test-signing-key-that-is-at-least-32-chars!!")

func signHS256(t *testing.T, subject, scope string, roles []string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "test",
		Subject:   subject,
		TokenID:   "tid",
		ClientID:  subject,
		Scope:     scope,
		Roles:     roles,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	})
	raw, err := jwtutil.Sign(claims, testKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func TestHS256_ValidToken_ReturnsClaims(t *testing.T) {
	v := hs256.NewVerifier(testKey)
	raw := signHS256(t, "alice", "read", []string{"admin"}, time.Minute)

	claims, err := v.Verify(raw)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "alice")
	}
	if claims.Scope != "read" {
		t.Errorf("scope: got %q, want %q", claims.Scope, "read")
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Errorf("roles: got %v, want [admin]", claims.Roles)
	}
}

func TestHS256_WrongKey_ReturnsTokenInvalid(t *testing.T) {
	raw := signHS256(t, "alice", "read", nil, time.Minute)
	v := hs256.NewVerifier([]byte("wrong-key-that-is-also-at-least-32-chars!!"))

	_, err := v.Verify(raw)

	if !errors.Is(err, jwtutil.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got: %v", err)
	}
}

func TestHS256_ExpiredToken_ReturnsTokenExpired(t *testing.T) {
	raw := signHS256(t, "alice", "read", nil, -time.Second) // already expired
	v := hs256.NewVerifier(testKey)

	_, err := v.Verify(raw)

	if !errors.Is(err, jwtutil.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestHS256_MalformedToken_ReturnsTokenMalformed(t *testing.T) {
	v := hs256.NewVerifier(testKey)

	_, err := v.Verify("not.a.jwt")

	if !errors.Is(err, jwtutil.ErrTokenMalformed) {
		t.Errorf("expected ErrTokenMalformed, got: %v", err)
	}
}

func TestHS256_EmptyKey_ReturnsTokenInvalid(t *testing.T) {
	v := hs256.NewVerifier(nil)
	raw := signHS256(t, "alice", "", nil, time.Minute)

	_, err := v.Verify(raw)

	if !errors.Is(err, jwtutil.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for empty key, got: %v", err)
	}
}
