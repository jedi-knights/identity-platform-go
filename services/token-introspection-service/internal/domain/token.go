package domain

// IntrospectionResult is the result of token introspection (RFC 7662)
type IntrospectionResult struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Scopes    []string `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
}

// TokenValidator defines how tokens are validated (Strategy pattern)
type TokenValidator interface {
	Validate(raw string) (*IntrospectionResult, error)
}
