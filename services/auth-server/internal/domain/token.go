package domain

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// ErrTokenNotFound is the sentinel returned by TokenRepository implementations
// when no token matches the given raw value. Callers use errors.Is to detect it.
var ErrTokenNotFound = errors.New("token not found")

// TokenType represents the type of token.
type TokenType string

const (
	// TokenTypeBearer is the RFC 6750 token type value. RFC 6750 §6.1.1 specifies
	// the registered "Bearer" value with a capital B — this matches what must appear
	// in the token_type field of RFC 6749 §5.1 token responses.
	TokenTypeBearer TokenType = "Bearer"
	TokenTypeOpaque TokenType = "opaque"
)

// Token represents an issued OAuth token.
//
// ActorType + AgentID (ADR-0015) classify the principal kind on the
// issued token. ActorType is "user" | "service" | "agent" matching the
// audit envelope and the jwtutil.Claims field of the same name; AgentID
// is set when ActorType is "agent" and equals the OAuth client_id today.
// Both are empty for tokens minted before ADR-0015 implementation.
type Token struct {
	ID          string
	ClientID    string
	Subject     string
	Issuer      string
	Audience    []string // RFC 9068 §2.2: resource server identifiers; nil when not set
	Scopes      []string
	Roles       []string // RBAC roles embedded in JWT; resolved at issuance
	Permissions []string // resolved permissions ("resource:action"); resolved at issuance
	ActorType   ActorType
	AgentID     string

	// Act is the RFC 8693 §4.1 delegation chain. Populated by the
	// token-exchange strategy by prepending the current actor to the
	// subject_token's chain; nil for every other grant type. Stored on
	// the domain Token so the audit emitter can record chain depth and
	// the token generator can lift it into the issued JWT.
	Act *Actor

	// AuthorizationDetails is the RFC 9396 §7 granted-details array
	// per ADR-0017. Set by the grant strategies when the caller
	// supplied the parameter; the RS256 token generator lifts it onto
	// the issued JWT and the introspection projection surfaces it for
	// resource servers that opt into the richer enforcement model.
	AuthorizationDetails []AuthorizationDetail

	ExpiresAt time.Time
	IssuedAt  time.Time
	TokenType TokenType
	Raw       string // JWT string or opaque token
}

// Actor is one hop of the RFC 8693 §4.1 actor chain (ADR-0016).
// Mirrors jwtutil.Actor; kept separate so the domain layer does not
// take a hard dependency on the jwt encoder.
type Actor struct {
	Sub       string
	ActorType ActorType
	AgentID   string
	ClientID  string
	Act       *Actor
}

// Depth reports the length of the actor chain rooted at a. A nil
// receiver returns 0.
func (a *Actor) Depth() int {
	d := 0
	for cursor := a; cursor != nil; cursor = cursor.Act {
		d++
	}
	return d
}

// IsExpired reports whether the token is expired relative to the current wall clock.
// Prefer IsExpiredAt in tests and anywhere a stable time reference is needed.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsExpiredAt reports whether the token is expired relative to the given time.
// Prefer this over IsExpired in tests to allow time injection.
func (t *Token) IsExpiredAt(now time.Time) bool {
	return now.After(t.ExpiresAt)
}

// HasScope reports whether the token was issued with the named scope.
func (t *Token) HasScope(scope string) bool {
	return slices.Contains(t.Scopes, scope)
}

// TokenRepository is the port for token persistence.
type TokenRepository interface {
	Save(ctx context.Context, token *Token) error
	FindByRaw(ctx context.Context, raw string) (*Token, error)
	Delete(ctx context.Context, raw string) error
}

// ErrRefreshTokenNotFound is returned by RefreshTokenRepository when no refresh
// token matches the given raw value.
var ErrRefreshTokenNotFound = errors.New("refresh token not found")

// RefreshToken represents an opaque refresh token issued alongside an access token.
// Refresh tokens are stored server-side (Redis) and rotated on each use per RFC 6749 §6.
// The client_credentials grant issues refresh tokens so the full grant flow can be
// demonstrated; RFC 6749 §4.4.3 says SHOULD NOT, which is advisory — this reference
// implementation issues them to make the flow testable.
type RefreshToken struct {
	ID        string
	Raw       string // opaque random hex value — never a JWT
	ClientID  string
	Subject   string
	Scopes    []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// RefreshTokenRepository is the port for refresh token persistence.
type RefreshTokenRepository interface {
	Save(ctx context.Context, token *RefreshToken) error
	FindByRaw(ctx context.Context, raw string) (*RefreshToken, error)
	Delete(ctx context.Context, raw string) error
}

// IntrospectResponse is the result of token introspection per RFC 7662.
// JTI and Audience are RFC 7662 §2.2 standard fields; both are omitted when empty.
type IntrospectResponse struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	JTI       string   `json:"jti,omitempty"`
	Audience  []string `json:"aud,omitempty"`

	// AuthorizationDetails echoes the RFC 9396 §10.1 granted-details
	// array. Omitted when empty so RAR-unaware resource servers see
	// the same shape they always have.
	AuthorizationDetails []json.RawMessage `json:"authorization_details,omitempty"`
}
