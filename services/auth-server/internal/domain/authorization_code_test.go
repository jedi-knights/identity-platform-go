//go:build unit

package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestAuthorizationCode_IsExpired_BeforeExpiry(t *testing.T) {
	// Arrange
	now := time.Now()
	code := &domain.AuthorizationCode{
		ExpiresAt: now.Add(30 * time.Second),
	}

	// Act
	got := code.IsExpiredAt(now)

	// Assert
	if got {
		t.Error("IsExpiredAt = true for code 30s from expiry, want false")
	}
}

func TestAuthorizationCode_IsExpired_AfterExpiry(t *testing.T) {
	// Arrange
	now := time.Now()
	code := &domain.AuthorizationCode{
		ExpiresAt: now.Add(-time.Second),
	}

	// Act
	got := code.IsExpiredAt(now)

	// Assert
	if !got {
		t.Error("IsExpiredAt = false for code 1s past expiry, want true")
	}
}

func TestAuthorizationCode_IsExpired_AtExpiryExact(t *testing.T) {
	// Arrange — exp == now is treated as expired (the boundary is exclusive on
	// the valid side; matches RFC 6749 §4.1.2's "MUST reject after expiry").
	now := time.Now()
	code := &domain.AuthorizationCode{ExpiresAt: now}

	// Act / Assert
	if !code.IsExpiredAt(now) {
		t.Error("IsExpiredAt at exact expiry = false, want true (inclusive boundary)")
	}
}

func TestAuthorizationCode_RequiresS256(t *testing.T) {
	// Arrange — S256 is the only PKCE method this platform accepts. Any
	// stored value other than "S256" is treated as invalid; the constructor
	// in application/authcode_issuer.go must reject other inputs at the
	// boundary so the field always carries the right value on round-trip.
	good := &domain.AuthorizationCode{CodeChallengeMethod: "S256"}
	plain := &domain.AuthorizationCode{CodeChallengeMethod: "plain"}
	empty := &domain.AuthorizationCode{CodeChallengeMethod: ""}

	// Act / Assert
	if !good.HasValidPKCEMethod() {
		t.Error("HasValidPKCEMethod = false for S256, want true")
	}
	if plain.HasValidPKCEMethod() {
		t.Error("HasValidPKCEMethod = true for plain, want false")
	}
	if empty.HasValidPKCEMethod() {
		t.Error("HasValidPKCEMethod = true for empty, want false")
	}
}

func TestErrAuthorizationCodeNotFound_Sentinel(t *testing.T) {
	// Arrange — the sentinel must be Is-comparable so callers can distinguish
	// "code never existed / already consumed / expired" from infrastructure
	// errors. The strategy uses errors.Is(err, ErrAuthorizationCodeNotFound)
	// to decide whether to trigger the replay-detection cascade.
	wrapped := errAuthorizationCodeNotFoundWrappedFor(t)

	// Act
	got := errors.Is(wrapped, domain.ErrAuthorizationCodeNotFound)

	// Assert
	if !got {
		t.Error("errors.Is(wrapped, ErrAuthorizationCodeNotFound) = false, want true")
	}
}

// errAuthorizationCodeNotFoundWrappedFor returns a wrapped error containing
// the sentinel. Test-local helper to keep the test focused on the Is-chain.
func errAuthorizationCodeNotFoundWrappedFor(t *testing.T) error {
	t.Helper()
	return mustWrap(domain.ErrAuthorizationCodeNotFound)
}

func mustWrap(err error) error { return wrappedErr{inner: err} }

type wrappedErr struct{ inner error }

func (w wrappedErr) Error() string { return "wrapped: " + w.inner.Error() }
func (w wrappedErr) Unwrap() error { return w.inner }
