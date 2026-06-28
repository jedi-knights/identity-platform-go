package domain

import (
	"context"
	"errors"
	"time"
)

// ErrLoginChallengeNotFound is returned by LoginChallengeRepository when a
// challenge with the requested ID does not exist (or has expired). Callers
// use errors.Is to distinguish this from infrastructure failures.
var ErrLoginChallengeNotFound = errors.New("login challenge not found")

// LoginChallenge is the server-side state of an in-flight authorize request
// (ADR-0011). When auth-server's /oauth/authorize receives a request from a
// relying party, it stores everything needed to resume the flow under an
// opaque ID and redirects the user-agent to login-ui with only that ID in
// the URL. Login-ui calls back through /internal/issue-code with the same
// ID once user authentication and consent are complete.
//
// The struct carries every field the ADR's full design uses — including
// SessionID and ConsentGranted that the consent flow will populate in a
// later commit — so the storage schema is stable across the whole ADR-0011
// rollout. Fields that the current sign-in-only flow does not write stay
// zero-valued without affecting correctness.
type LoginChallenge struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string

	// Prompt is the OIDC §3.1.2.1 prompt parameter, decomposed into its
	// individual values. Stored verbatim; behaviour gates live in the
	// /oauth/authorize handler.
	Prompt []string

	// MaxAge is the OIDC §3.1.2.1 max_age parameter (seconds). 0 means
	// "not requested". The /oauth/authorize handler may force re-auth
	// when the SSO session is older than this.
	MaxAge int

	// SessionID is populated by login-ui after a successful sign-in. The
	// /internal/issue-code handler cross-checks it against the SSO session
	// cookie carried on the same call to prevent a stolen challenge ID
	// from being redeemed without proof of the matching session.
	SessionID string

	// ConsentGranted is populated when the consent flow is implemented
	// (follow-up commit). It records the exact scope subset the user
	// approved — /internal/issue-code refuses to issue a code for any
	// scope outside this set.
	ConsentGranted []string

	// AuthorizationDetails is the RFC 9396 §2 authorization_details
	// array as parsed off the /oauth/authorize request (ADR-0017).
	// Persisted on the challenge so the granted-details follow the
	// auth code into the token at /oauth/token. Nil when the request
	// did not include the parameter — the auth-code grant then
	// issues a token without the claim.
	//
	// Today the consent flow is auto-approve (no UI narrowing), so
	// this field is the request's parsed array. When the consent
	// screen lands (follow-up commit), the narrowed-by-user subset
	// will overwrite this value before /internal/issue-code consumes
	// the challenge.
	AuthorizationDetails []AuthorizationDetail

	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpiredAt reports whether the challenge has passed its expiry at the
// supplied wall-clock time. Boundary semantics match AuthorizationCode:
// exp == now is treated as expired.
func (c *LoginChallenge) IsExpiredAt(now time.Time) bool {
	return !now.Before(c.ExpiresAt)
}

// LoginChallengeRepository is the persistence port behind LoginChallenge.
// Implementations must satisfy the same atomicity invariant as the
// AuthorizationCodeRepository: Consume is a single read-and-delete step so
// two concurrent /internal/issue-code calls cannot both succeed for the
// same challenge ID.
//
// Update is a separate operation needed by the consent flow (write
// ConsentGranted onto an in-flight challenge before redemption). Single-
// step Update is fine — the consent screen is per-user, so concurrent
// updates by different users would target different challenge IDs.
type LoginChallengeRepository interface {
	// Save persists a new challenge. TTL should be aligned to
	// ExpiresAt - now so the store does not retain stale entries.
	Save(ctx context.Context, c *LoginChallenge) error

	// Get reads a challenge by ID without removing it. Used by login-ui
	// to render the sign-in / consent screens before redemption. Returns
	// ErrLoginChallengeNotFound for unknown / expired IDs.
	Get(ctx context.Context, id string) (*LoginChallenge, error)

	// Update overwrites the stored record for ID. Returns
	// ErrLoginChallengeNotFound when the ID does not exist (e.g. a
	// concurrent Consume removed it).
	Update(ctx context.Context, c *LoginChallenge) error

	// Consume atomically reads and deletes the challenge identified by
	// ID. Returns ErrLoginChallengeNotFound for unknown / expired / already-
	// consumed IDs.
	Consume(ctx context.Context, id string) (*LoginChallenge, error)
}
