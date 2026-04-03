package testutil

import (
	"reflect"
	"testing"
)

// Logger is a minimal interface matching libs/logging.Logger,
// used so test helpers can accept loggers without importing that module.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	With(args ...any) Logger
}

// noopLogger is a Logger that discards all log output.
type noopLogger struct{}

func (noopLogger) Debug(_ string, _ ...any) {}
func (noopLogger) Info(_ string, _ ...any)  {}
func (noopLogger) Warn(_ string, _ ...any)  {}
func (noopLogger) Error(_ string, _ ...any) {}
func (n noopLogger) With(_ ...any) Logger   { return n }

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
