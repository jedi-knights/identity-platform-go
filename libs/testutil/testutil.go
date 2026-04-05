package testutil

import (
	"reflect"
	"testing"

	logginglib "github.com/ocrosby/identity-platform-go/libs/logging"
)

// Logger is an alias for logginglib.Logger so test helpers can use it
// interchangeably with the canonical logging interface without requiring
// callers to import libs/logging directly.
type Logger = logginglib.Logger

// Compile-time check that noopLogger (value form) implements logginglib.Logger.
// NewTestLogger returns the value form, so we assert against it — not the pointer.
var _ logginglib.Logger = noopLogger{}

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

// RequireNoError calls t.Fatal if err is non-nil and not a typed nil.
// A typed nil (e.g. (*T)(nil) stored in an error interface) is treated as absent:
// the interface itself is non-nil, but the underlying value is nil, so there is
// no real error to report. This matches the guard applied in libs/errors.Wrap.
func RequireNoError(t testing.TB, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if v := reflect.ValueOf(err); isNilableKind(v.Kind()) && v.IsNil() {
		return
	}
	t.Fatalf("unexpected error (%T): %v", err, err)
}

// AssertEqual calls t.Errorf if expected and actual are not deeply equal.
// The first argument is the expected value; the second is the actual value.
// Note: reflect.DeepEqual distinguishes nil slices from empty slices —
// AssertEqual(t, []string{}, nil) will fail.
func AssertEqual(t testing.TB, expected, actual any) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected %T(%v), got %T(%v)", expected, expected, actual, actual)
	}
}

// isNilableKind reports whether a reflect.Kind can hold a nil value,
// i.e. whether reflect.Value.IsNil() is safe to call on a value of that kind.
// This mirrors the same helper in libs/errors to guard against the typed-nil
// interface hazard consistently across the codebase.
func isNilableKind(k reflect.Kind) bool {
	switch k {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return true
	default:
		return false
	}
}
