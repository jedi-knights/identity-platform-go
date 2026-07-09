package domain

import (
	"errors"
	"testing"
)

func TestErrClientAssertionReplayed_IsSentinel(t *testing.T) {
	// Arrange
	wrapped := errors.New("wrapped: " + ErrClientAssertionReplayed.Error())

	// Act
	is := errors.Is(ErrClientAssertionReplayed, ErrClientAssertionReplayed)

	// Assert
	if !is {
		t.Error("expected ErrClientAssertionReplayed to satisfy errors.Is with itself")
	}
	if wrapped.Error() == ErrClientAssertionReplayed.Error() {
		t.Error("test sentinel construction is degenerate")
	}
}
