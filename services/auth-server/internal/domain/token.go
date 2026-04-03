package domain

import "time"

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
	Save(token *Token) error
	FindByRaw(raw string) (*Token, error)
	Delete(raw string) error
}
