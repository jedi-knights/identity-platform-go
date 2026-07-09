package domain

import (
	"context"
	"errors"
	"time"
)

// ErrClientAssertionReplayed is returned by
// ClientAssertionReplayRepository.MarkUsed when the presented jti has
// already been recorded — RFC 7523 §3 point 8's replay-protection
// requirement (ADR-0023).
var ErrClientAssertionReplayed = errors.New("client assertion jti already used")

// ClientAssertionReplayRepository is the persistence port for RFC 7523
// JWT-bearer client-assertion replay protection (ADR-0023). Unlike every
// other "atomic consume" repository in this codebase (AuthorizationCode,
// PushedAuthorizationRequest, DeviceAuthorization — all read-then-delete),
// this is "insert if absent": a jti is recorded once and never read back:
// the fact that it exists at all is the record.
type ClientAssertionReplayRepository interface {
	// MarkUsed atomically records jti as consumed, with a TTL through
	// expiresAt (the assertion's own exp claim — once the assertion
	// itself would be rejected as expired, remembering its jti serves no
	// purpose). Returns ErrClientAssertionReplayed if jti was already
	// recorded by an earlier call.
	MarkUsed(ctx context.Context, jti string, expiresAt time.Time) error
}
