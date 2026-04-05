package domain

import (
	"context"
	"time"
)

// TokenType represents the type of token.
type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeOpaque TokenType = "opaque"
)

// Token represents an issued OAuth token.
type Token struct {
	ID        string
	ClientID  string
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	TokenType TokenType
	Raw       string // JWT string or opaque token
}

func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsExpiredAt reports whether the token is expired relative to the given time.
// Prefer this over IsExpired in tests to allow time injection.
func (t *Token) IsExpiredAt(now time.Time) bool {
	return now.After(t.ExpiresAt)
}

func (t *Token) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// TokenRepository is the port for token persistence.
type TokenRepository interface {
	Save(ctx context.Context, token *Token) error
	FindByRaw(ctx context.Context, raw string) (*Token, error)
	Delete(ctx context.Context, raw string) error
}

// IntrospectResponse is the result of token introspection per RFC 7662.
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}
