//go:build unit

package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestPushedAuthorizationRequest_IsExpired_BeforeExpiry(t *testing.T) {
	// Arrange
	now := time.Now()
	par := &domain.PushedAuthorizationRequest{ExpiresAt: now.Add(30 * time.Second)}

	// Act
	got := par.IsExpiredAt(now)

	// Assert
	if got {
		t.Error("IsExpiredAt = true for a request 30s from expiry, want false")
	}
}

func TestPushedAuthorizationRequest_IsExpired_AfterExpiry(t *testing.T) {
	// Arrange
	now := time.Now()
	par := &domain.PushedAuthorizationRequest{ExpiresAt: now.Add(-time.Second)}

	// Act
	got := par.IsExpiredAt(now)

	// Assert
	if !got {
		t.Error("IsExpiredAt = false for a request 1s past expiry, want true")
	}
}

func TestPushedAuthorizationRequest_IsExpired_AtExpiryExact(t *testing.T) {
	// Arrange — exp == now is treated as expired, matching
	// AuthorizationCode.IsExpiredAt's inclusive boundary.
	now := time.Now()
	par := &domain.PushedAuthorizationRequest{ExpiresAt: now}

	// Act / Assert
	if !par.IsExpiredAt(now) {
		t.Error("IsExpiredAt at exact expiry = false, want true (inclusive boundary)")
	}
}

func TestErrPushedAuthorizationRequestNotFound_Sentinel(t *testing.T) {
	// Arrange — must be Is-comparable so the authorize handler can
	// distinguish "unknown/expired/already-consumed request_uri" from an
	// infrastructure error.
	wrapped := wrappedErr{inner: domain.ErrPushedAuthorizationRequestNotFound}

	// Act
	got := errors.Is(wrapped, domain.ErrPushedAuthorizationRequestNotFound)

	// Assert
	if !got {
		t.Error("errors.Is(wrapped, ErrPushedAuthorizationRequestNotFound) = false, want true")
	}
}
