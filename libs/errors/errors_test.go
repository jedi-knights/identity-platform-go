package errors_test

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		code    apperrors.ErrorCode
		message string
	}{
		{"not found", apperrors.ErrCodeNotFound, "item not found"},
		{"unauthorized", apperrors.ErrCodeUnauthorized, "access denied"},
		{"forbidden", apperrors.ErrCodeForbidden, "access forbidden"},
		{"bad request", apperrors.ErrCodeBadRequest, "bad request"},
		{"internal", apperrors.ErrCodeInternal, "server error"},
		{"conflict", apperrors.ErrCodeConflict, "resource conflict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := apperrors.New(tt.code, tt.message)
			if err == nil {
				t.Fatal("expected non-nil error")
			}
			if err.Code() != tt.code {
				t.Errorf("expected code %s, got %s", tt.code, err.Code())
			}
			if err.Message() != tt.message {
				t.Errorf("expected message %q, got %q", tt.message, err.Message())
			}
			if err.Unwrap() != nil {
				t.Error("expected nil wrapped error")
			}
		})
	}
}

func TestWrap(t *testing.T) {
	cause := errors.New("db error")
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "database failure", cause)
	if err.Unwrap() != cause {
		t.Fatal("Unwrap should return cause")
	}
	want := "INTERNAL: database failure: db error"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestWrap_ErrorsAsChain(t *testing.T) {
	cause := errors.New("db error")
	wrapped := apperrors.Wrap(apperrors.ErrCodeInternal, "database failure", cause)
	outer := fmt.Errorf("handler: %w", wrapped)

	var ae *apperrors.AppError
	if !errors.As(outer, &ae) {
		t.Fatal("errors.As should find AppError through outer wrapping")
	}
	if ae.Code() != apperrors.ErrCodeInternal {
		t.Errorf("expected ErrCodeInternal, got %s", ae.Code())
	}
	if !errors.Is(outer, cause) {
		t.Fatal("errors.Is should find original cause through chain")
	}
}

func TestWrap_NestedAppError(t *testing.T) {
	inner := apperrors.New(apperrors.ErrCodeNotFound, "not found")
	outer := apperrors.Wrap(apperrors.ErrCodeInternal, "operation failed", inner)

	var ae *apperrors.AppError
	if !errors.As(outer, &ae) {
		t.Fatal("errors.As should find AppError")
	}
	// errors.As stops at the first match — the outer AppError, not the inner one.
	if ae.Code() != apperrors.ErrCodeInternal {
		t.Errorf("expected outer code ErrCodeInternal, got %s", ae.Code())
	}

	// The inner AppError is still reachable by unwrapping one level.
	var innerAE *apperrors.AppError
	if !errors.As(outer.Unwrap(), &innerAE) {
		t.Fatal("inner AppError should be reachable via Unwrap")
	}
	if innerAE.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("expected inner code ErrCodeNotFound, got %s", innerAE.Code())
	}
}

func TestAppError_Unwrap_NilReceiver(t *testing.T) {
	var e *apperrors.AppError
	if got := e.Unwrap(); got != nil {
		t.Errorf("nil AppError.Unwrap() = %v, want nil", got)
	}
}

func TestWrap_TypedNilCause(t *testing.T) {
	// Wrap must normalise a typed nil to an untyped nil so callers cannot
	// accidentally produce a three-part Error() string ending in "<nil AppError>".
	var typedNil *apperrors.AppError
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", typedNil)
	if err.Unwrap() != nil {
		t.Fatalf("typed-nil cause should be normalised to nil, got %v", err.Unwrap())
	}
	want := "INTERNAL: op failed"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestWrap_FmtWrappedTypedNilCause documents that a typed-nil *AppError passed
// through fmt.Errorf("%w", ...) produces a non-nil *fmt.wrapError. Wrap cannot
// detect this — the wrapError is genuinely non-nil and is stored as the cause.
// This is a known limitation: Wrap only normalises typed nils at the direct
// interface boundary, not deep inside an error chain.
func TestWrap_FmtWrappedTypedNilCause(t *testing.T) {
	fmtWrapped := fmt.Errorf("ctx: %w", (*apperrors.AppError)(nil))
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "op", fmtWrapped)
	// The fmt-wrapped value is non-nil; Wrap stores it as-is.
	if err.Unwrap() == nil {
		t.Fatal("fmt-wrapped typed nil should be stored as a non-nil cause — behaviour changed, update doc comment")
	}
	// The Error() string includes the fmt wrapper, not a bare "<nil AppError>".
	want := "INTERNAL: op: ctx: <nil AppError>"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestWrap_ReflectInterface documents that reflect.ValueOf applied to an error
// interface parameter always unwraps the interface box and returns the kind of
// the concrete type — never reflect.Interface. This confirms that the
// reflect.Interface arm in isNilableKind is unreachable via a cause error param.
func TestWrap_ReflectInterface(t *testing.T) {
	var cause error = apperrors.New(apperrors.ErrCodeInternal, "msg")
	v := reflect.ValueOf(cause)
	// Assert the exact kind — *AppError is a pointer, so ValueOf yields Pointer.
	// This also confirms ValueOf never returns Interface for a concrete error value.
	if v.Kind() != reflect.Pointer {
		t.Fatalf("reflect.ValueOf on *AppError should return reflect.Pointer, got %v", v.Kind())
	}
}

func TestWrap_TypedNilCause_OtherType(t *testing.T) {
	// The typed-nil guard must work for any nilable error type, not just *AppError.
	var pathNil *os.PathError
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", pathNil)
	if err.Unwrap() != nil {
		t.Fatalf("typed-nil *os.PathError cause should be normalised to nil, got %v", err.Unwrap())
	}
	want := "INTERNAL: op failed"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// mapError is a map-based error type — nilable, satisfies error via value receiver.
type mapError map[string]string

func (e mapError) Error() string { return "map error" }

func TestWrap_TypedNilCause_Map(t *testing.T) {
	// map is nilable; a nil mapError must be normalised to an untyped nil.
	var m mapError
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "op", m)
	if err.Unwrap() != nil {
		t.Fatalf("typed-nil map cause should be normalised to nil, got %v", err.Unwrap())
	}
	want := "INTERNAL: op"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// funcError is a function-type error — nilable, satisfies error via value receiver.
type funcError func() string

func (f funcError) Error() string {
	if f == nil {
		return "<nil funcError>"
	}
	return f()
}

func TestWrap_TypedNilCause_Func(t *testing.T) {
	// func is nilable; a nil funcError must be normalised to an untyped nil.
	var f funcError
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "op", f)
	if err.Unwrap() != nil {
		t.Fatalf("typed-nil func cause should be normalised to nil, got %v", err.Unwrap())
	}
	want := "INTERNAL: op"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// valueError is a value-receiver error type — rare but valid Go.
// Wrap must store it as-is and must not panic on the reflect.IsNil guard.
type valueError struct{ msg string }

func (e valueError) Error() string { return e.msg }

func TestWrap_ValueTypeError(t *testing.T) {
	err := apperrors.Wrap(apperrors.ErrCodeInternal, "op", valueError{"oops"})
	if err.Unwrap() == nil {
		t.Fatal("value-type error cause should be stored, not dropped")
	}
	want := "INTERNAL: op: oops"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestWrap_NilCause(t *testing.T) {
	err := apperrors.Wrap(apperrors.ErrCodeBadRequest, "bad input", nil)
	if err.Unwrap() != nil {
		t.Error("Unwrap should return nil when cause was nil")
	}
	want := "BAD_REQUEST: bad input"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *apperrors.AppError
		want string
	}{
		{
			name: "without wrapped error",
			err:  apperrors.New(apperrors.ErrCodeBadRequest, "bad input"),
			want: "BAD_REQUEST: bad input",
		},
		{
			name: "with wrapped error",
			err:  apperrors.Wrap(apperrors.ErrCodeInternal, "wrapped", errors.New("underlying")),
			want: "INTERNAL: wrapped: underlying",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppError_Error_NilReceiver(t *testing.T) {
	var e *apperrors.AppError
	want := "<nil AppError>"
	if got := e.Error(); got != want {
		t.Errorf("nil AppError.Error() = %q, want %q", got, want)
	}
}

func TestAppError_Accessors(t *testing.T) {
	err := apperrors.New(apperrors.ErrCodeNotFound, "not found")
	if err.Code() != apperrors.ErrCodeNotFound {
		t.Errorf("Code() = %v, want ErrCodeNotFound", err.Code())
	}
	if err.Message() != "not found" {
		t.Errorf("Message() = %q, want %q", "not found", err.Message())
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap() on New result should be nil")
	}

	var nilErr *apperrors.AppError
	if nilErr.Code() != apperrors.ErrorCode("") {
		t.Error("nil receiver Code() should return zero ErrorCode")
	}
	if nilErr.Message() != "" {
		t.Error("nil receiver Message() should return empty string")
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"direct not-found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), true},
		{"wrapped not-found", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeNotFound, "inner")), true},
		{"other code", apperrors.New(apperrors.ErrCodeInternal, "internal"), false},
		{"plain error", errors.New("plain"), false},
		{"nil error", nil, false},
		{"two-level wrapped not-found", fmt.Errorf("handler: %w", fmt.Errorf("service: %w", apperrors.New(apperrors.ErrCodeNotFound, "deep"))), true},
		// errors.As stops at the first *AppError; outer code shadows the inner NOT_FOUND.
		{"outer code shadows inner not-found", apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", apperrors.New(apperrors.ErrCodeNotFound, "inner")), false},
		// typed-nil is normalised to nil by Wrap — result is INTERNAL with no cause.
		{"typed-nil cause", apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", (*apperrors.AppError)(nil)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"unauthorized", apperrors.New(apperrors.ErrCodeUnauthorized, "unauthorized"), true},
		{"wrapped unauthorized", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeUnauthorized, "inner")), true},
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
		{"nil error", nil, false},
		{"two-level wrapped unauthorized", fmt.Errorf("handler: %w", fmt.Errorf("service: %w", apperrors.New(apperrors.ErrCodeUnauthorized, "deep"))), true},
		{"outer code shadows inner unauthorized", apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", apperrors.New(apperrors.ErrCodeUnauthorized, "inner")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsUnauthorized(tt.err); got != tt.want {
				t.Errorf("IsUnauthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsForbidden(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"forbidden", apperrors.New(apperrors.ErrCodeForbidden, "forbidden"), true},
		{"wrapped forbidden", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeForbidden, "inner")), true},
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
		{"nil error", nil, false},
		{"two-level wrapped forbidden", fmt.Errorf("handler: %w", fmt.Errorf("service: %w", apperrors.New(apperrors.ErrCodeForbidden, "deep"))), true},
		{"outer code shadows inner forbidden", apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", apperrors.New(apperrors.ErrCodeForbidden, "inner")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsForbidden(tt.err); got != tt.want {
				t.Errorf("IsForbidden() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBadRequest(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"bad request", apperrors.New(apperrors.ErrCodeBadRequest, "bad request"), true},
		{"wrapped bad request", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeBadRequest, "inner")), true},
		{"not found", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
		{"nil error", nil, false},
		{"two-level wrapped bad request", fmt.Errorf("handler: %w", fmt.Errorf("service: %w", apperrors.New(apperrors.ErrCodeBadRequest, "deep"))), true},
		{"outer code shadows inner bad request", apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", apperrors.New(apperrors.ErrCodeBadRequest, "inner")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsBadRequest(tt.err); got != tt.want {
				t.Errorf("IsBadRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConflict(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"conflict error", apperrors.New(apperrors.ErrCodeConflict, "conflict"), true},
		{"wrapped conflict", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeConflict, "inner")), true},
		{"not found error", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
		{"nil error", nil, false},
		{"two-level wrapped conflict", fmt.Errorf("handler: %w", fmt.Errorf("service: %w", apperrors.New(apperrors.ErrCodeConflict, "deep"))), true},
		{"outer code shadows inner conflict", apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", apperrors.New(apperrors.ErrCodeConflict, "inner")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsConflict(tt.err); got != tt.want {
				t.Errorf("IsConflict() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsInternal(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"internal error", apperrors.New(apperrors.ErrCodeInternal, "internal"), true},
		{"wrapped internal", fmt.Errorf("outer: %w", apperrors.New(apperrors.ErrCodeInternal, "inner")), true},
		{"not found error", apperrors.New(apperrors.ErrCodeNotFound, "not found"), false},
		{"nil error", nil, false},
		{"two-level wrapped internal", fmt.Errorf("handler: %w", fmt.Errorf("service: %w", apperrors.New(apperrors.ErrCodeInternal, "deep"))), true},
		{"outer code shadows inner internal", apperrors.Wrap(apperrors.ErrCodeNotFound, "op failed", apperrors.New(apperrors.ErrCodeInternal, "inner")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.IsInternal(tt.err); got != tt.want {
				t.Errorf("IsInternal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidCode(t *testing.T) {
	tests := []struct {
		name string
		code apperrors.ErrorCode
		want bool
	}{
		{"not found", apperrors.ErrCodeNotFound, true},
		{"unauthorized", apperrors.ErrCodeUnauthorized, true},
		{"forbidden", apperrors.ErrCodeForbidden, true},
		{"bad request", apperrors.ErrCodeBadRequest, true},
		{"internal", apperrors.ErrCodeInternal, true},
		{"conflict", apperrors.ErrCodeConflict, true},
		{"unknown", apperrors.ErrorCode("TYPO"), false},
		{"empty", apperrors.ErrorCode(""), false},
		{"prefix of valid code", apperrors.ErrorCode("NOT_FOUND_EXTRA"), false}, // exact-match semantics
		{"valid code prefix only", apperrors.ErrorCode("NOT"), false},           // exact-match semantics
		{"null byte embedded", apperrors.ErrorCode("NOT_FOUND\x00"), false},     // no normalisation: switch is byte-exact
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperrors.ValidCode(tt.code); got != tt.want {
				t.Errorf("ValidCode(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// predicateBenchCases covers all six Is* predicates for table-driven benchmarks.
// Array literal prevents accidental appends and encodes the fixed size in the type.
// Declared as a package-level var (not const) because it holds func values.
var predicateBenchCases = [6]struct {
	name string
	fn   func(error) bool
	code apperrors.ErrorCode
}{
	{"IsNotFound", apperrors.IsNotFound, apperrors.ErrCodeNotFound},
	{"IsUnauthorized", apperrors.IsUnauthorized, apperrors.ErrCodeUnauthorized},
	{"IsForbidden", apperrors.IsForbidden, apperrors.ErrCodeForbidden},
	{"IsBadRequest", apperrors.IsBadRequest, apperrors.ErrCodeBadRequest},
	{"IsConflict", apperrors.IsConflict, apperrors.ErrCodeConflict},
	{"IsInternal", apperrors.IsInternal, apperrors.ErrCodeInternal},
}

func BenchmarkIsCode_Direct(b *testing.B) {
	for _, p := range predicateBenchCases {
		// err is constructed once per sub-benchmark, outside the timed loop.
		// b.Run resets the timer at the start of each sub-benchmark, so this
		// allocation is intentionally excluded from the measured window.
		err := apperrors.New(p.code, "msg")
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			// b.Loop() (Go 1.24+) handles timer reset automatically; prefer over for range b.N.
			for b.Loop() {
				_ = p.fn(err)
			}
		})
	}
}

func BenchmarkIsCode_Wrapped(b *testing.B) {
	for _, p := range predicateBenchCases {
		// err is constructed once per sub-benchmark, outside the timed loop.
		// The fmt.Errorf allocation is intentionally excluded from the measured window.
		err := fmt.Errorf("outer: %w", apperrors.New(p.code, "msg"))
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			// b.Loop() (Go 1.24+) handles timer reset automatically; prefer over for range b.N.
			for b.Loop() {
				_ = p.fn(err)
			}
		})
	}
}

func TestValidCode_ZeroAllocs(t *testing.T) {
	// ValidCode takes ErrorCode (a string type, not an interface), so race
	// instrumentation does not add allocations — this test is stable under -race.
	allocs := testing.AllocsPerRun(100, func() {
		_ = apperrors.ValidCode(apperrors.ErrCodeNotFound)
	})
	if allocs != 0 {
		t.Errorf("ValidCode allocates %.0f times per call, want 0", allocs)
	}
}

func BenchmarkValidCode(b *testing.B) {
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically; prefer over for range b.N.
	for b.Loop() {
		_ = apperrors.ValidCode(apperrors.ErrCodeNotFound)
	}
}

func BenchmarkValidCode_Miss(b *testing.B) {
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically; prefer over for range b.N.
	for b.Loop() {
		_ = apperrors.ValidCode(apperrors.ErrorCode("UNKNOWN"))
	}
}

// assertOneAlloc asserts that fn allocates exactly once per call over 100 runs.
func assertOneAlloc(t *testing.T, label string, fn func()) {
	t.Helper()
	allocs := testing.AllocsPerRun(100, fn)
	switch {
	case allocs < 1:
		t.Errorf("%s: got %.0f allocs per call, want 1 (possible escape-analysis change — struct may have moved to stack)", label, allocs)
	case allocs > 1:
		t.Errorf("%s: got %.0f allocs per call, want 1 (unexpected heap escapes)", label, allocs)
	}
}

// TestWrap_AppErrorCause_OneAlloc asserts that wrapping a concrete non-nil *AppError
// cause costs exactly one allocation (the new AppError struct). The fast-path type
// assertion must avoid reflect overhead on this common case.
func TestWrap_AppErrorCause_OneAlloc(t *testing.T) {
	cause := apperrors.New(apperrors.ErrCodeNotFound, "not found")
	assertOneAlloc(t, "Wrap with *AppError cause", func() {
		_ = apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", cause)
	})
}

func BenchmarkWrap_WithCause(b *testing.B) {
	// cause is a *errors.errorString, not a *AppError, so it bypasses the fast-path
	// *AppError type assertion and reaches the reflect branch. Since the cause is
	// non-nil, the reflect check returns immediately and the cost is the same
	// single allocation (the new *AppError struct) as the fast path.
	cause := errors.New("db error")
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically; prefer over for range b.N.
	for b.Loop() {
		_ = apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", cause)
	}
}

func BenchmarkWrap_TypedNil(b *testing.B) {
	// Exercises the *AppError fast-path for a typed nil (NOT the reflect path).
	// Expected: 1 allocation (the *AppError struct). The cause is normalised to nil
	// before being stored, but the struct itself is still heap-allocated.
	// See TestWrap_AppErrorCause_OneAlloc for the contractual assertion.
	// For the reflect path, see BenchmarkWrap_TypedNil_ReflectPath.
	var cause *apperrors.AppError
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically; prefer over for range b.N.
	for b.Loop() {
		_ = apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", cause)
	}
}

// TestWrap_ReflectPath_OneAlloc asserts that wrapping a typed-nil cause that reaches
// the reflect branch (any nilable type other than *AppError) still costs exactly one
// allocation — the new AppError struct. The reflect.ValueOf call must not add extras.
func TestWrap_ReflectPath_OneAlloc(t *testing.T) {
	// Pointer kind — reflect reads the pointer directly from the interface word.
	var ptrCause *os.PathError
	assertOneAlloc(t, "Wrap (reflect path, pointer typed-nil)", func() {
		_ = apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", ptrCause)
	})

	// Map kind — the pointer sub-case above already enforces the strict 1-alloc
	// contract for the reflect branch itself. This sub-case confirms that map kind
	// specifically does not add unbounded allocations — the bound is <= 2 because
	// map-to-interface boxing can produce a second allocation under the race
	// detector's shadow-memory instrumentation.
	// Regression signal: if this ever reports 3+, something escaped that shouldn't.
	var mapCause mapError
	mapAllocs := testing.AllocsPerRun(100, func() {
		_ = apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", mapCause)
	})
	if mapAllocs > 2 {
		t.Errorf("Wrap (reflect path, map typed-nil) allocates %.0f times per call, want <= 2", mapAllocs)
	}
}

func BenchmarkWrap_TypedNil_ReflectPath(b *testing.B) {
	// Exercises the reflect normalisation path — *os.PathError bypasses the *AppError
	// fast path and reaches reflect.ValueOf. Expected: 1 allocation (the *AppError struct).
	var cause *os.PathError
	b.ReportAllocs()
	// b.Loop() (Go 1.24+) handles timer reset automatically; prefer over for range b.N.
	for b.Loop() {
		_ = apperrors.Wrap(apperrors.ErrCodeInternal, "op failed", cause)
	}
}
