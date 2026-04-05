package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode is a string code identifying the category of error.
type ErrorCode string

const (
	ErrCodeNotFound     ErrorCode = "NOT_FOUND"
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden    ErrorCode = "FORBIDDEN"
	ErrCodeBadRequest   ErrorCode = "BAD_REQUEST"
	ErrCodeInternal     ErrorCode = "INTERNAL"
	ErrCodeConflict     ErrorCode = "CONFLICT"
)

// AppError is a structured application error.
type AppError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates an AppError without a wrapped cause.
func New(code ErrorCode, msg string) *AppError {
	return &AppError{Code: code, Message: msg}
}

// Wrap creates an AppError that wraps an underlying error.
func Wrap(code ErrorCode, msg string, err error) *AppError {
	return &AppError{Code: code, Message: msg, Err: err}
}

// IsNotFound reports whether err is an AppError with ErrCodeNotFound.
func IsNotFound(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.Code == ErrCodeNotFound
}

// IsUnauthorized reports whether err is an AppError with ErrCodeUnauthorized.
func IsUnauthorized(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.Code == ErrCodeUnauthorized
}

// IsForbidden reports whether err is an AppError with ErrCodeForbidden.
func IsForbidden(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.Code == ErrCodeForbidden
}

// IsBadRequest reports whether err is an AppError with ErrCodeBadRequest.
func IsBadRequest(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.Code == ErrCodeBadRequest
}

// IsConflict reports whether err is an AppError with ErrCodeConflict.
func IsConflict(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.Code == ErrCodeConflict
}

// IsInternal reports whether err is an AppError with ErrCodeInternal.
func IsInternal(err error) bool {
	var e *AppError
	return errors.As(err, &e) && e.Code == ErrCodeInternal
}

// HTTPStatus maps an AppError code to an HTTP status code.
// Non-AppError values return 500.
func HTTPStatus(err error) int {
	var e *AppError
	if !errors.As(err, &e) {
		return http.StatusInternalServerError
	}
	switch e.Code {
	case ErrCodeNotFound:
		return http.StatusNotFound
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case ErrCodeForbidden:
		return http.StatusForbidden
	case ErrCodeBadRequest:
		return http.StatusBadRequest
	case ErrCodeConflict:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
