package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// SAMLBearerStrategy implements the RFC 7522 §2.1 SAML 2.0 Bearer Assertion
// Grant per ADR-0026: a SAML assertion identifying the resource owner is
// exchanged for an access token. The client authenticates itself exactly
// like every other grant (client_id/client_secret); the assertion is a
// separate artifact, not a client-authentication mechanism (that's RFC
// 7522 §2.2, out of scope here).
//
// Unlike ClientCredentialsStrategy, no refresh token is issued — see the
// ADR's Consequences section for why a long-lived refresh token would
// outlive the trust boundary an individual short-lived assertion
// establishes.
type SAMLBearerStrategy struct {
	clientAuth       ports.ClientAuthenticator
	tokenRepo        domain.TokenRepository
	refreshTokenRepo domain.RefreshTokenRepository
	tokenGen         TokenGenerator
	validator        *SAMLBearerValidator
	tokenEndpointURL string // expected AudienceRestriction / SubjectConfirmationData.Recipient
	ttl              time.Duration
}

// NewSAMLBearerStrategy wires the strategy with its collaborators.
// tokenEndpointURL is this auth-server's own token endpoint, used as the
// required RFC 7522 §3 audience/recipient value.
func NewSAMLBearerStrategy(
	clientAuth ports.ClientAuthenticator,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	validator *SAMLBearerValidator,
	tokenEndpointURL string,
	ttl time.Duration,
) *SAMLBearerStrategy {
	return &SAMLBearerStrategy{
		clientAuth:       clientAuth,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		validator:        validator,
		tokenEndpointURL: tokenEndpointURL,
		ttl:              ttl,
	}
}

// Supports reports whether this strategy handles the saml2-bearer grant type.
func (s *SAMLBearerStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeSAML2Bearer
}

// Handle authenticates the client, validates the presented SAML assertion
// against the client's registered trusted-issuer certificate, and issues an
// access token representing the assertion's subject.
func (s *SAMLBearerStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	if req.SAMLAssertion == "" {
		return nil, fmt.Errorf("%w: assertion is required", ErrInvalidRequest)
	}

	client, err := s.clientAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !client.HasGrantType(domain.GrantTypeSAML2Bearer) {
		return nil, fmt.Errorf("%w: grant type not allowed for client", ErrUnauthorizedClient)
	}
	if client.TrustedIssuerCert == "" {
		return nil, fmt.Errorf("%w: client has no trusted issuer certificate registered", ErrInvalidGrant)
	}

	validated, err := s.validator.Validate([]byte(req.SAMLAssertion), client.TrustedIssuerCert, s.tokenEndpointURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidGrant, err.Error())
	}

	scopes, err := resolveSAMLScopes(client, req.Scopes)
	if err != nil {
		return nil, err
	}

	return s.issueToken(ctx, client, validated, scopes)
}

// resolveSAMLScopes intersects requested scopes with the client's
// registered scopes — mirrors ClientCredentialsStrategy.resolveScopes.
// Kept as its own small function rather than shared across strategy types,
// consistent with how RefreshTokenStrategy and AuthorizationCodeStrategy
// each already have their own scope/claim resolution rather than a shared
// helper.
func resolveSAMLScopes(client *domain.Client, requested []string) ([]string, error) {
	scopes := requested
	if len(scopes) == 0 {
		scopes = client.Scopes
	}
	for _, scope := range scopes {
		if !client.HasScope(scope) {
			return nil, apperrors.New(apperrors.ErrCodeForbidden, fmt.Sprintf("scope not allowed: %s", scope))
		}
	}
	return scopes, nil
}

func (s *SAMLBearerStrategy) issueToken(ctx context.Context, client *domain.Client, validated *ValidatedSAMLAssertion, scopes []string) (*domain.GrantResponse, error) {
	tokenID, err := generateID()
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "generating token id", err)
	}
	now := time.Now()
	token := &domain.Token{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  validated.Subject,
		Scopes:   scopes,
		// The assertion's Subject is the human resource owner the SAML IdP
		// vouched for — mirrors AuthorizationCodeStrategy's ADR-0015
		// reasoning that such tokens represent a user, not the client.
		ActorType: domain.ActorTypeUser,
		ExpiresAt: now.Add(s.ttl),
		IssuedAt:  now,
		TokenType: domain.TokenTypeBearer,
	}
	raw, err := s.tokenGen.Generate(ctx, token)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "token generation failed", err)
	}
	token.Raw = raw
	if err := s.tokenRepo.Save(ctx, token); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "token save failed", err)
	}

	return &domain.GrantResponse{
		AccessToken: raw,
		TokenType:   string(domain.TokenTypeBearer),
		ExpiresIn:   int(s.ttl.Seconds()),
		Scope:       strings.Join(scopes, " "),
		ActorType:   domain.ActorTypeUser,
		Subject:     validated.Subject,
	}, nil
}
