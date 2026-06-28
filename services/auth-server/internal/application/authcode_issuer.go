package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// Compile-time interface check — the issuer is invoked by ADR-0011's
// /oauth/authorize handler via the ports.AuthorizationCodeIssuer interface,
// so a signature drift here would surface at the wiring layer.
var _ ports.AuthorizationCodeIssuer = (*authorizationCodeIssuer)(nil)

// authCodeEntropyBytes is the CSPRNG entropy used per ADR-0009. 32 bytes is
// 256 bits — more than enough to make brute force impossible within the
// 60-second default TTL.
const authCodeEntropyBytes = 32

// authorizationCodeIssuer is the platform's AuthorizationCodeIssuer
// implementation. The issuer's contract is narrow: validate that the inputs
// are present and that the PKCE method is the one this platform supports
// (S256 only), generate a fresh 32-byte CSPRNG code, stamp issuance + expiry,
// and persist via the repository.
//
// Inputs are pre-validated at the authorize endpoint (ADR-0011) — scopes
// already intersected with the client's set, redirect URI already matched
// byte-exact, user identity already established. The issuer trusts those
// invariants but still rejects empty values (defense in depth — if the
// caller forgot a field, a half-populated code in the store is worse than
// a hard error).
type authorizationCodeIssuer struct {
	repo domain.AuthorizationCodeRepository
	ttl  time.Duration
}

// NewAuthorizationCodeIssuer wires the issuer to the code repository.
// The ttl is the code's lifetime; ADR-0009 recommends 60 seconds.
func NewAuthorizationCodeIssuer(repo domain.AuthorizationCodeRepository, ttl time.Duration) *authorizationCodeIssuer {
	return &authorizationCodeIssuer{repo: repo, ttl: ttl}
}

// Issue validates the request, generates a CSPRNG-backed opaque code, and
// persists it. Returns the raw code as the value the caller (ADR-0011's
// authorize handler) will redirect the user-agent with as ?code=<raw>.
func (i *authorizationCodeIssuer) Issue(ctx context.Context, req ports.IssueCodeRequest) (string, error) {
	if err := validateIssueRequest(req); err != nil {
		return "", err
	}
	raw, err := generateAuthCode()
	if err != nil {
		return "", fmt.Errorf("issuing authorization code: %w", err)
	}
	now := time.Now()
	code := &domain.AuthorizationCode{
		Code:                 raw,
		ClientID:             req.ClientID,
		Subject:              req.Subject,
		RedirectURI:          req.RedirectURI,
		Scopes:               append([]string(nil), req.Scopes...),
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Nonce:                req.Nonce,
		AuthorizationDetails: append([]domain.AuthorizationDetail(nil), req.AuthorizationDetails...),
		IssuedAt:             now,
		ExpiresAt:            now.Add(i.ttl),
	}
	if err := i.repo.Save(ctx, code); err != nil {
		return "", fmt.Errorf("saving authorization code: %w", err)
	}
	return raw, nil
}

// validateIssueRequest enforces the four invariants the issuer cares about:
// every required identifier is present and PKCE method is S256. Field-name
// errors are intentional — the authorize handler logs them, and the
// distinction between "missing client_id" and "missing redirect_uri" helps
// triage misconfigured callers.
func validateIssueRequest(req ports.IssueCodeRequest) error {
	switch {
	case req.ClientID == "":
		return errors.New("issuing authorization code: ClientID is required")
	case req.Subject == "":
		return errors.New("issuing authorization code: Subject is required")
	case req.RedirectURI == "":
		return errors.New("issuing authorization code: RedirectURI is required")
	case req.CodeChallengeMethod != "S256":
		return fmt.Errorf("issuing authorization code: CodeChallengeMethod %q is not supported (S256 only)", req.CodeChallengeMethod)
	}
	return nil
}

// generateAuthCode returns 32 bytes of CSPRNG entropy hex-encoded.
// The resulting string is 64 lowercase hex characters.
func generateAuthCode() (string, error) {
	b := make([]byte, authCodeEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
