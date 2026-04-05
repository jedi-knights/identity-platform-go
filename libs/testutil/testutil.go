package testutil

import (
	"reflect"
	"testing"

	logginglib "github.com/ocrosby/identity-platform-go/libs/logging"
)

// Logger is an alias for logginglib.Logger so test helpers can use it
// interchangeably with the canonical logging interface.
type Logger = logginglib.Logger

// Compile-time check that noopLogger implements logginglib.Logger.
var _ logginglib.Logger = (*noopLogger)(nil)

// noopLogger is a Logger that discards all log output.
type noopLogger struct{}

func (noopLogger) Debug(_ string, _ ...any)          {}
func (noopLogger) Info(_ string, _ ...any)           {}
func (noopLogger) Warn(_ string, _ ...any)           {}
func (noopLogger) Error(_ string, _ ...any)          {}
func (n noopLogger) With(_ ...any) logginglib.Logger { return n }

// NewTestLogger returns a no-op Logger suitable for unit tests.
func NewTestLogger() Logger {
	return noopLogger{}
}

// RequireNoError calls t.Fatal if err is not nil.
func RequireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertEqual calls t.Errorf if expected and actual are not deeply equal.
func AssertEqual(t testing.TB, expected, actual any) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}
