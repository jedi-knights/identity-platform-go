package domain

import "context"

// IntrospectionResult is the result of token introspection (RFC 7662).
// Scope is a space-delimited string per RFC 9068 §2.2.3.1 and RFC 7662 §2.2.
type IntrospectionResult struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Issuer    string `json:"iss,omitempty"`
}

// TokenValidator defines how tokens are validated (Strategy pattern).
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (*IntrospectionResult, error)
}
