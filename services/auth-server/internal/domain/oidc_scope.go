package domain

import "slices"

// ScopeOpenID is the OIDC gateway scope (OIDC Core §3.1.2.1). Its presence
// in an access-token request signals OIDC mode: the token endpoint issues
// an id_token alongside the access token, and the strategy invokes the
// UserClaimsFetcher to populate identity claims.
//
// Without ScopeOpenID, the platform behaves as a plain OAuth 2.0
// authorization server — no id_token, /userinfo returns 403.
const ScopeOpenID = "openid"

// ScopeProfile selects the OIDC "profile" claim set per OIDC Core §5.4
// (this platform implements the name + updated_at subset; other entries
// like family_name, middle_name, picture, birthdate are not modeled
// because the User domain type has no fields for them — see ADR-0010).
const ScopeProfile = "profile"

// ScopeEmail selects email + email_verified per OIDC Core §5.4.
const ScopeEmail = "email"

// HasScope reports whether s contains target. Convenience for the strategy
// and the /userinfo handler, both of which gate behaviour on individual
// OIDC scope values.
func HasScope(s []string, target string) bool {
	return slices.Contains(s, target)
}
