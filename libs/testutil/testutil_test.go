package testutil_test

import (
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/testutil"
)

// spyT records whether Fatal or Error was called.
// The embedded testing.TB must be initialised with the real *testing.T from the
// enclosing test — never left as nil. Any un-overridden method on a nil interface
// field panics at runtime rather than producing a test failure.
//
// Note: Fatalf sets a flag but does NOT call runtime.Goexit(). Code that runs
// after a Fatalf call inside the function under test will still execute. This is
// intentional for spy purposes; it means spyT is unsuitable for testing helpers
// that rely on Fatalf being terminal.
type spyT struct {
	testing.TB
	fataled bool
	errored bool
}

func (s *spyT) Fatalf(format string, args ...any) {
	s.fataled = true
	_ = format
	_ = args
}

func (s *spyT) Errorf(format string, args ...any) {
	s.errored = true
	_ = format
	_ = args
}

func (s *spyT) Helper() {}

// typedNilErr is a pointer-receiver error type used to construct typed-nil
// error values for the RequireNoError typed-nil guard tests.
type typedNilErr struct{}

func (e *typedNilErr) Error() string { return "typed nil error" }

func TestRequireNoError_NoError(t *testing.T) {
	spy := &spyT{TB: t}
	testutil.RequireNoError(spy, nil)
	if spy.fataled {
		t.Error("expected no Fatal when err is nil")
	}
}

func TestRequireNoError_WithError(t *testing.T) {
	spy := &spyT{TB: t}
	testutil.RequireNoError(spy, errors.New("something broke"))
	if !spy.fataled {
		t.Error("expected Fatal when err is non-nil")
	}
}

func TestRequireNoError_TypedNilDoesNotFatal(t *testing.T) {
	// A typed nil (*typedNilErr)(nil) assigned to an error interface produces a
	// non-nil interface value, so a naive err != nil check would call Fatal.
	// RequireNoError must guard against this — a typed nil is logically absent.
	spy := &spyT{TB: t}
	var e *typedNilErr // typed nil
	testutil.RequireNoError(spy, e)
	if spy.fataled {
		t.Error("RequireNoError must not call Fatal for a typed nil error")
	}
}

func TestAssertEqual(t *testing.T) {
	tests := []struct {
		name     string
		expected any
		actual   any
		wantErr  bool
	}{
		{"equal ints", 42, 42, false},
		{"unequal ints", 42, 99, true},
		// reflect.DeepEqual distinguishes nil slices from empty slices, so this
		// call intentionally produces an error. See AssertEqual godoc.
		{"reflect_DeepEqual_nil_slice_not_equal_empty_slice", []string{}, []string(nil), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &spyT{TB: t}
			testutil.AssertEqual(spy, tt.expected, tt.actual)
			if tt.wantErr != spy.errored {
				t.Errorf("wantErr=%v errored=%v", tt.wantErr, spy.errored)
			}
		})
	}
}

func TestNewTestLogger(t *testing.T) {
	l := testutil.NewTestLogger()
	if l == nil {
		t.Fatal("NewTestLogger returned nil")
	}
	// All methods must be callable without panicking.
	l.Debug("debug", "k", "v")
	l.Info("info", "k", "v")
	l.Warn("warn", "k", "v")
	l.Error("error", "k", "v")

	sub := l.With("key", "value")
	if sub == nil {
		t.Fatal("With returned nil")
	}
	sub.Info("sub-logger call")
}
