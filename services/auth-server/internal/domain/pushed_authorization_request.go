package domain

import (
	"context"
	"errors"
	"time"
)

// ErrPushedAuthorizationRequestNotFound is returned by
// PushedAuthorizationRequestRepository.Consume when no request with the
// given request_uri exists — unknown, expired, or already consumed.
// errors.Is is used to distinguish this from infrastructure errors.
var ErrPushedAuthorizationRequestNotFound = errors.New("pushed authorization request not found")

// PushedAuthorizationRequest is the server-side record for a pushed
// authorization request (RFC 9126 §2.1). Fields mirror authorizeRequest's
// raw form values exactly — /oauth/authorize's existing
// parseAuthorizeRequest/validateAuthorizeParams/ParseAuthorizationDetails
// pipeline re-parses these identically whether they arrived via the query
// string or a consumed PushedAuthorizationRequest, so there is exactly one
// code path that turns raw strings into a validated request regardless of
// transport.
//
// RequestURI is the opaque token returned to the client
// (urn:ietf:params:oauth:request_uri:<random>) and the storage key —
// Consume looks up by this value and must delete-on-read in one atomic
// step, mirroring AuthorizationCode's anti-replay contract.
type PushedAuthorizationRequest struct {
	RequestURI           string
	ClientID             string
	ResponseType         string
	RedirectURI          string
	Scope                string
	State                string
	Nonce                string
	CodeChallenge        string
	CodeChallengeMethod  string
	Prompt               string
	MaxAge               string
	AuthorizationDetails string

	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpiredAt reports whether the request is past its expiry as of now.
// Inclusive on the expired side, matching AuthorizationCode.IsExpiredAt.
func (p *PushedAuthorizationRequest) IsExpiredAt(now time.Time) bool {
	return !now.Before(p.ExpiresAt)
}

// PushedAuthorizationRequestRepository is the persistence port for pushed
// authorization requests. Implementations must satisfy the same
// correctness invariants as AuthorizationCodeRepository: Consume is an
// atomic read-and-delete, and Save sets a TTL aligned to ExpiresAt.
type PushedAuthorizationRequestRepository interface {
	// Save persists the request. The store may set a TTL equal to
	// (ExpiresAt - now) so entries expire automatically.
	Save(ctx context.Context, req *PushedAuthorizationRequest) error

	// Consume atomically reads and deletes the request identified by
	// requestURI. Returns ErrPushedAuthorizationRequestNotFound for
	// unknown / expired / already-consumed values.
	Consume(ctx context.Context, requestURI string) (*PushedAuthorizationRequest, error)
}
