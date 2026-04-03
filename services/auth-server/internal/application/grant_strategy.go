package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// GrantStrategy defines the interface for handling grant types (Strategy pattern).
type GrantStrategy interface {
	Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error)
	Supports(gt domain.GrantType) bool
}

// GrantStrategyRegistry holds all grant strategies (Registry/Factory pattern).
type GrantStrategyRegistry struct {
	strategies []GrantStrategy
}

func NewGrantStrategyRegistry(strategies ...GrantStrategy) *GrantStrategyRegistry {
	return &GrantStrategyRegistry{strategies: strategies}
}

func (r *GrantStrategyRegistry) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	for _, s := range r.strategies {
		if s.Supports(req.GrantType) {
			return s.Handle(ctx, req)
		}
	}
	return nil, fmt.Errorf("unsupported grant type: %s", req.GrantType)
}

// ClientCredentialsStrategy handles the client_credentials grant.
type ClientCredentialsStrategy struct {
	clientRepo domain.ClientRepository
	tokenRepo  domain.TokenRepository
	tokenGen   TokenGenerator
	ttl        time.Duration
}

func NewClientCredentialsStrategy(
	clientRepo domain.ClientRepository,
	tokenRepo domain.TokenRepository,
	tokenGen TokenGenerator,
	ttl time.Duration,
) *ClientCredentialsStrategy {
	return &ClientCredentialsStrategy{
		clientRepo: clientRepo,
		tokenRepo:  tokenRepo,
		tokenGen:   tokenGen,
		ttl:        ttl,
	}
}

func (s *ClientCredentialsStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeClientCredentials
}

func (s *ClientCredentialsStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	client, err := s.clientRepo.FindByID(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	if client.Secret != req.ClientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	if !client.HasGrantType(domain.GrantTypeClientCredentials) {
		return nil, fmt.Errorf("grant type not allowed for client")
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = client.Scopes
	}

	for _, scope := range scopes {
		if !client.HasScope(scope) {
			return nil, fmt.Errorf("scope not allowed: %s", scope)
		}
	}

	now := time.Now()
	token := &domain.Token{
		ClientID:  req.ClientID,
		Subject:   req.ClientID,
		Scopes:    scopes,
		ExpiresAt: now.Add(s.ttl),
		IssuedAt:  now,
		TokenType: domain.TokenTypeBearer,
	}

	raw, err := s.tokenGen.Generate(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token generation failed: %w", err)
	}
	token.Raw = raw

	if err := s.tokenRepo.Save(token); err != nil {
		return nil, fmt.Errorf("token save failed: %w", err)
	}

	scopeStr := ""
	for i, sc := range scopes {
		if i > 0 {
			scopeStr += " "
		}
		scopeStr += sc
	}

	return &domain.GrantResponse{
		AccessToken: raw,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.ttl.Seconds()),
		Scope:       scopeStr,
	}, nil
}

// AuthorizationCodeStrategy handles the authorization_code grant (stub).
type AuthorizationCodeStrategy struct {
	clientRepo domain.ClientRepository
	tokenRepo  domain.TokenRepository
	tokenGen   TokenGenerator
	ttl        time.Duration
}

func NewAuthorizationCodeStrategy(
	clientRepo domain.ClientRepository,
	tokenRepo domain.TokenRepository,
	tokenGen TokenGenerator,
	ttl time.Duration,
) *AuthorizationCodeStrategy {
	return &AuthorizationCodeStrategy{
		clientRepo: clientRepo,
		tokenRepo:  tokenRepo,
		tokenGen:   tokenGen,
		ttl:        ttl,
	}
}

func (s *AuthorizationCodeStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeAuthorizationCode
}

// Handle is a stub; full PKCE implementation would validate code_verifier against stored code_challenge.
func (s *AuthorizationCodeStrategy) Handle(_ context.Context, _ domain.GrantRequest) (*domain.GrantResponse, error) {
	return nil, fmt.Errorf("authorization_code grant not yet fully implemented")
}
