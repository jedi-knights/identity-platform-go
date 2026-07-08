package domain

import (
	"errors"
	"testing"
	"time"
)

func TestDeviceAuthorization_IsExpiredAt(t *testing.T) {
	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "before expiry", now: time.Unix(100, 0), want: false},
		{name: "at expiry boundary", now: time.Unix(200, 0), want: true},
		{name: "after expiry", now: time.Unix(300, 0), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			auth := &DeviceAuthorization{ExpiresAt: time.Unix(200, 0)}

			// Act
			got := auth.IsExpiredAt(tt.now)

			// Assert
			if got != tt.want {
				t.Errorf("IsExpiredAt(%v) = %v, want %v", tt.now, got, tt.want)
			}
		})
	}
}

func TestErrDeviceAuthorizationNotFound_IsSentinel(t *testing.T) {
	// Arrange
	wrapped := errors.New("wrapped: " + ErrDeviceAuthorizationNotFound.Error())

	// Act
	is := errors.Is(ErrDeviceAuthorizationNotFound, ErrDeviceAuthorizationNotFound)

	// Assert
	if !is {
		t.Error("expected ErrDeviceAuthorizationNotFound to satisfy errors.Is with itself")
	}
	if wrapped.Error() == ErrDeviceAuthorizationNotFound.Error() {
		t.Error("test sentinel construction is degenerate")
	}
}
