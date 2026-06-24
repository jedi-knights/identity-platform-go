package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// TokenIssuer is the inbound port for token issuance.
type TokenIssuer interface {
	IssueToken(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error)
}

// TokenIntrospector is the inbound port for token introspection.
type TokenIntrospector interface {
	Introspect(ctx context.Context, raw string) (*domain.IntrospectResponse, error)
}

// TokenRevoker is the inbound port for token revocation.
type TokenRevoker interface {
	Revoke(ctx context.Context, raw string) error
}

// IssueCodeRequest is the input to AuthorizationCodeIssuer.Issue. All fields
// are populated by the authorize-endpoint handler (ADR-0011) after user
// authentication, consent capture, and PKCE/scope validation. The issuer
// itself enforces only one rule on these fields — CodeChallengeMethod must
// be "S256" — and then stamps issuance + expiry time onto the stored record.
//
// RedirectURI is byte-exact equal to the value the client presented at
// /oauth/authorize; the token-endpoint exchange will compare the form value
// against the stored value (ADR-0009 §"Redirect URI matching policy").
//
// Nonce is empty when the request did not include "openid" in scope or did
// not supply a nonce — the OIDC ID-token issuer (ADR-0010) copies the field
// straight through, omitting the claim when empty.
type IssueCodeRequest struct {
	ClientID            string
	Subject             string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// AuthorizationCodeIssuer mints a fresh authorization code, persists it via
// the domain repository, and returns the raw code string. ADR-0011's
// /oauth/authorize handler invokes this once user identity and consent are
// established.
type AuthorizationCodeIssuer interface {
	Issue(ctx context.Context, req IssueCodeRequest) (string, error)
}
