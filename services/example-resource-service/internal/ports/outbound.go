// Package ports defines outbound port interfaces for the example-resource-service.
package ports

import "context"

// IntrospectionResult holds the fields the resource service needs from token introspection.
// It mirrors the RFC 7662 response but is scoped to what this service actually uses,
// keeping the resource service independent of the token-introspection-service domain package.
// Roles and Permissions are non-standard extensions populated from JWT claims when the
// token was issued with RBAC context. When absent, the local PolicyChecker fallback is used.
type IntrospectionResult struct {
	Active      bool
	Subject     string
	ClientID    string
	Scope       string   // space-delimited per RFC 9068
	Audience    []string // RFC 7662 §2.2: aud claim from the token; nil when not set
	Roles       []string // RBAC roles from JWT claims; nil when not present
	Permissions []string // resolved permissions ("resource:action"); nil when not present
}

// TokenIntrospector is the outbound port for validating access tokens.
// Implementations may call token-introspection-service over HTTP (production)
// or validate JWTs locally (fallback for local dev without the full stack).
type TokenIntrospector interface {
	// Introspect validates the raw token and returns its metadata.
	// Returns a result with Active=false (never an error) when the token is invalid,
	// expired, or revoked — consistent with RFC 7662 §2.2.
	Introspect(ctx context.Context, raw string) (*IntrospectionResult, error)
}

// PolicyChecker checks whether a subject is authorized to perform an action on a resource.
// It wraps the authorization-policy-service POST /evaluate endpoint (RFC-style RBAC).
// When nil, the resource service skips policy evaluation and relies on scope alone.
type PolicyChecker interface {
	// Evaluate returns true if the policy service grants the subject access to perform
	// action on the named resource. Infrastructure errors are returned as non-nil error.
	Evaluate(ctx context.Context, subjectID, resource, action string) (bool, error)
}
