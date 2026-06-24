package domain

import (
	"context"
	"errors"
	"time"
)

// ErrAuthorizationCodeNotFound is returned by AuthorizationCodeRepository.Consume
// when no code with the requested raw value exists in the store. Callers must
// not treat this as a benign "miss" — it is the trigger condition for the
// replay-detection cascade described in ADR-0009. errors.Is is used to
// distinguish this from infrastructure errors.
var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

// AuthorizationCode is the server-side record for an OAuth 2.1 authorization
// code (RFC 6749 §1.3.1, OAuth 2.1 §4.1). It binds the redirect URI, scope
// set, PKCE challenge, and OIDC nonce to a single opaque token; redemption
// at the token endpoint cross-checks every binding before issuing tokens
// (ADR-0009 §"Token-endpoint exchange — validation order").
//
// The Code field is the opaque random hex value handed back to the user
// agent. It is also the storage key — Consume looks up by this value and
// must delete-on-read in one atomic step (memory: map.delete under mutex;
// redis: GET+DEL Lua script) so two concurrent token-endpoint requests
// cannot both succeed.
type AuthorizationCode struct {
	Code                string
	ClientID            string
	Subject             string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	IssuedAt            time.Time
	ExpiresAt           time.Time
}

// IsExpiredAt reports whether the code is past its expiry as of now. The
// boundary is inclusive on the expired side — a code whose ExpiresAt equals
// now is treated as expired (RFC 6749 §4.1.2 "MUST reject after expiry").
func (c *AuthorizationCode) IsExpiredAt(now time.Time) bool {
	return !now.Before(c.ExpiresAt)
}

// HasValidPKCEMethod reports whether the stored challenge method is S256.
// The platform mandates S256 universally (ADR-0009); any other value is
// rejected at the authorize endpoint before the record is saved, so seeing
// a non-S256 method here at exchange time indicates store corruption.
func (c *AuthorizationCode) HasValidPKCEMethod() bool {
	return c.CodeChallengeMethod == "S256"
}

// AuthorizationCodeRepository is the persistence port for authorization
// codes. Implementations must satisfy two correctness invariants:
//
//   - Consume is atomic: read-and-delete in a single operation. Two
//     concurrent calls for the same code MUST NOT both return a non-nil
//     code. The Redis adapter uses a Lua script; the memory adapter holds
//     the mutex across the lookup and the delete.
//   - Save sets a TTL aligned to the code's ExpiresAt so the store does not
//     grow without bound. Expired entries do not need to be observably
//     deleted — they only need to be unreachable to Consume.
type AuthorizationCodeRepository interface {
	// Save persists the code. The store may set a TTL equal to
	// (ExpiresAt - now) so entries expire automatically.
	Save(ctx context.Context, code *AuthorizationCode) error

	// Consume atomically reads and deletes the code identified by raw.
	// Returns ErrAuthorizationCodeNotFound for unknown / expired / already-
	// consumed codes. The token-endpoint exchange path uses Consume; the
	// replay-detection path uses errors.Is on the returned error.
	Consume(ctx context.Context, raw string) (*AuthorizationCode, error)
}
