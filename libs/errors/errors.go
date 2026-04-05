// Package errors provides structured application errors for the identity platform.
// The central type is [AppError], which pairs an [ErrorCode] with a human-readable
// message and an optional wrapped cause. Use [New] for errors without a cause and
// [Wrap] when propagating an underlying error with added context.
//
// Errors produced by this package participate in the standard Go error chain.
// Use [errors.As] and [errors.Is] to inspect wrapped errors, and the Is* predicates
// (e.g. [IsNotFound]) as a convenience for the most common code checks.
package errors

import (
	"errors"
	"fmt"
	"reflect"
)

// ErrorCode is a string code identifying the category of error.
type ErrorCode string

// Predeclared error codes used throughout the identity platform. Each code
// maps to an HTTP status in libs/httputil. Use [ValidCode] to check that an
// externally-supplied code is one of these values before constructing an AppError.
const (
	ErrCodeNotFound     ErrorCode = "NOT_FOUND"    // resource does not exist; maps to HTTP 404
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED" // missing or invalid credentials; maps to HTTP 401
	ErrCodeForbidden    ErrorCode = "FORBIDDEN"    // identity known but access denied; maps to HTTP 403
	ErrCodeBadRequest   ErrorCode = "BAD_REQUEST"  // malformed or invalid request; maps to HTTP 400
	ErrCodeInternal     ErrorCode = "INTERNAL"     // unexpected server failure; maps to HTTP 500
	ErrCodeConflict     ErrorCode = "CONFLICT"     // state conflict (e.g. duplicate create); maps to HTTP 409
)

// Compile-time assertion: *AppError must satisfy the error interface.
var _ error = (*AppError)(nil)

// AppError is a structured application error.
// Fields are unexported to prevent mutation after construction; use [AppError.Code],
// [AppError.Message], and [AppError.Unwrap] to inspect values.
type AppError struct {
	// code identifies the category of the error. It determines the HTTP status
	// code when the error is written to an HTTP response via httputil.WriteError.
	code ErrorCode
	// message is the human-readable description returned to API clients.
	// It must not contain internal details such as SQL errors or file paths.
	message string
	// err is the optional underlying cause. Access it via [AppError.Unwrap].
	err error
}

// Code returns the error category. Returns the zero ErrorCode on a nil receiver.
func (e *AppError) Code() ErrorCode {
	if e == nil {
		return ErrorCode("")
	}
	return e.code
}

// Message returns the human-readable description. Returns "" on a nil receiver.
func (e *AppError) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}

// Error returns a string representation of the error in the form
// "CODE: message" or "CODE: message: cause" when a cause is present.
// Calling Error on a nil *AppError returns "<nil AppError>".
// Note: this nil-receiver path is only reachable when holding the value as a
// *AppError directly; a nil *AppError stored in an error interface is non-nil
// and will not reach this path.
func (e *AppError) Error() string {
	if e == nil {
		return "<nil AppError>"
	}
	if e.err != nil {
		return fmt.Sprintf("%s: %s: %s", e.code, e.message, e.err)
	}
	return fmt.Sprintf("%s: %s", e.code, e.message)
}

// Unwrap returns the underlying cause passed to [Wrap], or nil if this
// AppError was created with [New] or wrapped a nil cause.
// Unwrap on a nil *AppError returns nil.
// This method makes AppError participate in the errors.As and errors.Is chain.
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// New creates an AppError with the given code and message and never returns nil.
// The returned error has no wrapped cause; Unwrap returns nil.
// code must be one of the predeclared [ErrorCode] constants; passing a
// zero-value or arbitrary code produces a structurally valid but semantically
// undefined AppError whose Error string will have no meaningful code prefix.
func New(code ErrorCode, msg string) *AppError {
	return &AppError{code: code, message: msg}
}

// Wrap creates an AppError that wraps cause under the given code and message.
// Callers can retrieve cause via errors.Unwrap or errors.As.
// code must be one of the predeclared [ErrorCode] constants; see [New] for
// the consequences of passing a zero-value or arbitrary code.
//
// If cause is nil (untyped or typed) it is treated as absent: Unwrap returns nil
// and Error produces a two-part string. Typed nils (e.g. (*T)(nil) assigned to
// an error variable) are normalised to untyped nil at the point of storage so
// callers cannot accidentally produce a three-part string ending in "<nil AppError>".
// Struct-valued causes (non-nilable kinds) are always stored as-is; this package
// does not inspect beyond the interface boundary.
//
// Limitation: a typed nil passed through fmt.Errorf("%w", typedNil) is NOT
// normalised. fmt.Errorf wraps the typed nil in a non-nil *fmt.wrapError, which
// Wrap receives as a genuinely non-nil cause and stores as-is. This is an
// inherent limitation of the approach — Wrap cannot inspect inside the fmt wrapper.
func Wrap(code ErrorCode, msg string, cause error) *AppError {
	if cause != nil {
		// Fast path: *AppError is the most common cause type — avoid reflect entirely.
		if ae, ok := cause.(*AppError); ok {
			if ae == nil {
				cause = nil
			}
		} else {
			// General path: use reflect to detect typed nils of other nilable kinds
			// (chan, func, map, slice, unsafe.Pointer). IsNil panics on non-nilable
			// kinds (e.g. struct value receivers), so guard with Kind() first.
			if v := reflect.ValueOf(cause); isNilableKind(v.Kind()) && v.IsNil() {
				cause = nil
			}
		}
	}
	return &AppError{code: code, message: msg, err: cause}
}

// isNilableKind reports whether a reflect.Kind can hold a nil value,
// i.e. whether reflect.Value.IsNil() is safe to call on a value of that kind.
//
// Scope: this function is intentionally narrow. It is safe only when called with a
// reflect.Value obtained from reflect.ValueOf(cause) where cause is a concrete error
// value (not an arbitrary any). reflect.ValueOf on a concrete error never returns
// Interface kind (see TestWrap_ReflectInterface), so Interface is correctly excluded.
// If this helper is ever reused for arbitrary any values, Interface must be added.
func isNilableKind(k reflect.Kind) bool {
	switch k {
	// Chan, Func, Map, Pointer, Slice: the common nilable kinds reachable via an error interface.
	// UnsafePointer: nilable since Go 1.18; cannot satisfy the error interface directly,
	// but included so IsNil is safe to call if this helper is ever reused outside Wrap.
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return true
	default:
		return false
	}
}

// ValidCode reports whether c is one of the predeclared [ErrorCode] constants.
// It is intended for use at API boundaries where an ErrorCode is received from
// an external source and must be validated before constructing an AppError.
// Callers should reject the request (e.g. return [ErrCodeBadRequest]) when
// ValidCode returns false rather than constructing an AppError with an unknown code.
func ValidCode(c ErrorCode) bool {
	switch c {
	case ErrCodeNotFound, ErrCodeUnauthorized, ErrCodeForbidden,
		ErrCodeBadRequest, ErrCodeInternal, ErrCodeConflict:
		return true
	default:
		return false
	}
}

// IsNotFound reports whether the first [AppError] in err's chain has [ErrCodeNotFound].
// If an AppError with a different code appears earlier in the chain, it returns false
// even if a deeper AppError has ErrCodeNotFound.
func IsNotFound(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.code == ErrCodeNotFound
}

// IsUnauthorized reports whether the first [AppError] in err's chain has [ErrCodeUnauthorized].
// If an AppError with a different code appears earlier in the chain, it returns false
// even if a deeper AppError has ErrCodeUnauthorized.
func IsUnauthorized(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.code == ErrCodeUnauthorized
}

// IsForbidden reports whether the first [AppError] in err's chain has [ErrCodeForbidden].
// If an AppError with a different code appears earlier in the chain, it returns false
// even if a deeper AppError has ErrCodeForbidden.
func IsForbidden(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.code == ErrCodeForbidden
}

// IsBadRequest reports whether the first [AppError] in err's chain has [ErrCodeBadRequest].
// If an AppError with a different code appears earlier in the chain, it returns false
// even if a deeper AppError has ErrCodeBadRequest.
func IsBadRequest(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.code == ErrCodeBadRequest
}

// IsConflict reports whether the first [AppError] in err's chain has [ErrCodeConflict].
// If an AppError with a different code appears earlier in the chain, it returns false
// even if a deeper AppError has ErrCodeConflict.
func IsConflict(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.code == ErrCodeConflict
}

// IsInternal reports whether the first [AppError] in err's chain has [ErrCodeInternal].
// If an AppError with a different code appears earlier in the chain, it returns false
// even if a deeper AppError has ErrCodeInternal.
func IsInternal(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.code == ErrCodeInternal
}
