package domain

import "context"

// IntrospectionResult is the result of token introspection per RFC 7662.
// Scope is a space-delimited string per RFC 9068 §2.2.3.1 and RFC 7662 §2.2.
// Roles and Permissions are non-standard extensions populated from JWT claims
// when the token was issued with RBAC context. Resource services use these
// for local authorization evaluation without an outbound policy service call.
type IntrospectionResult struct {
	Active      bool     `json:"active"`
	ClientID    string   `json:"client_id,omitempty"`
	Subject     string   `json:"sub,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	ExpiresAt   int64    `json:"exp,omitempty"`
	IssuedAt    int64    `json:"iat,omitempty"`
	TokenType   string   `json:"token_type,omitempty"`
	Issuer      string   `json:"iss,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// TokenValidator defines how tokens are validated (Strategy pattern).
type TokenValidator interface {
	// Validate parses and validates a raw JWT string.
	// Per RFC 7662 §2.2, token validity failures (expired, malformed, wrong signature)
	// must return an IntrospectionResult with Active=false, not an error.
	// A non-nil error signals an infrastructure failure — the caller should treat
	// it as inactive and log it rather than propagating it to the HTTP response.
	Validate(ctx context.Context, raw string) (*IntrospectionResult, error)
}

// RevocationChecker checks whether a token has been revoked.
// It queries the same Redis keyspace written by auth-server.
// A token is considered active if its key exists; a missing key means it was revoked or never issued.
type RevocationChecker interface {
	IsActive(ctx context.Context, raw string) (bool, error)
}
