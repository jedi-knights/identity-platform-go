package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// ErrUnsupportedGrantType is returned when the requested grant type has no registered strategy.
var ErrUnsupportedGrantType = errors.New("unsupported grant type")

// GrantStrategy defines the interface for handling grant types (Strategy pattern).
type GrantStrategy interface {
	Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error)
	Supports(gt domain.GrantType) bool
}

// GrantStrategyRegistry holds all grant strategies (Registry/Factory pattern).
type GrantStrategyRegistry struct {
	strategies []GrantStrategy
}

// NewGrantStrategyRegistry creates a registry containing all provided strategies.
func NewGrantStrategyRegistry(strategies ...GrantStrategy) *GrantStrategyRegistry {
	return &GrantStrategyRegistry{strategies: strategies}
}

// Handle dispatches the grant request to the first matching strategy.
// Returns ErrUnsupportedGrantType when no strategy supports the grant type.
func (r *GrantStrategyRegistry) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	for _, s := range r.strategies {
		if s.Supports(req.GrantType) {
			return s.Handle(ctx, req)
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedGrantType, req.GrantType)
}

// ClientCredentialsStrategy handles the client_credentials grant.
type ClientCredentialsStrategy struct {
	clientAuth       ports.ClientAuthenticator
	tokenRepo        domain.TokenRepository
	refreshTokenRepo domain.RefreshTokenRepository
	tokenGen         TokenGenerator
	permsFetcher     ports.SubjectPermissionsFetcher // nil = no roles/permissions in JWT
	ttl              time.Duration
	refreshTTL       time.Duration
}

// NewClientCredentialsStrategy creates a ClientCredentialsStrategy.
// permsFetcher may be nil — when nil, tokens are issued without roles/permissions claims.
func NewClientCredentialsStrategy(
	clientAuth ports.ClientAuthenticator,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	permsFetcher ports.SubjectPermissionsFetcher,
	ttl time.Duration,
	refreshTTL time.Duration,
) *ClientCredentialsStrategy {
	return &ClientCredentialsStrategy{
		clientAuth:       clientAuth,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		permsFetcher:     permsFetcher,
		ttl:              ttl,
		refreshTTL:       refreshTTL,
	}
}

// Supports reports whether this strategy handles the given grant type.
func (s *ClientCredentialsStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeClientCredentials
}

func (s *ClientCredentialsStrategy) validateClient(ctx context.Context, req domain.GrantRequest) (*domain.Client, error) {
	client, err := s.clientAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		// Preserve the specific error code from the authenticator (Unauthorized vs Internal).
		return nil, err
	}
	if !client.HasGrantType(domain.GrantTypeClientCredentials) {
		return nil, apperrors.New(apperrors.ErrCodeForbidden, "grant type not allowed for client")
	}
	return client, nil
}

func (s *ClientCredentialsStrategy) resolveScopes(client *domain.Client, requested []string) ([]string, error) {
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

// issueRefreshToken generates, persists, and returns a new opaque refresh token.
// Extracted from Handle to keep Handle's cyclomatic complexity within bounds.
func (s *ClientCredentialsStrategy) issueRefreshToken(ctx context.Context, clientID string, scopes []string, now time.Time) (string, error) {
	refreshRaw, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token raw value", err)
	}
	refreshID, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token id", err)
	}
	rt := &domain.RefreshToken{
		ID:        refreshID,
		Raw:       refreshRaw,
		ClientID:  clientID,
		Subject:   clientID,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.refreshTTL),
	}
	if err := s.refreshTokenRepo.Save(ctx, rt); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "saving refresh token", err)
	}
	return refreshRaw, nil
}

// issueAccessToken generates a token ID, builds the domain.Token, signs it as a JWT,
// and persists it. Extracted from Handle to keep Handle's cyclomatic complexity
// within bounds.
func (s *ClientCredentialsStrategy) issueAccessToken(ctx context.Context, clientID string, scopes, roles, permissions []string, now time.Time) (string, error) {
	tokenID, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating token id", err)
	}
	token := &domain.Token{
		ID:          tokenID,
		ClientID:    clientID,
		Subject:     clientID,
		Scopes:      scopes,
		Roles:       roles,
		Permissions: permissions,
		ExpiresAt:   now.Add(s.ttl),
		IssuedAt:    now,
		TokenType:   domain.TokenTypeBearer,
	}
	raw, err := s.tokenGen.Generate(ctx, token)
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "token generation failed", err)
	}
	token.Raw = raw
	if err := s.tokenRepo.Save(ctx, token); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "token save failed", err)
	}
	return raw, nil
}

// Handle processes a client_credentials grant request.
// It authenticates the client, resolves scopes, optionally fetches RBAC claims,
// issues an access token, and issues a refresh token.
func (s *ClientCredentialsStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	client, err := s.validateClient(ctx, req)
	if err != nil {
		return nil, err
	}

	scopes, err := s.resolveScopes(client, req.Scopes)
	if err != nil {
		return nil, err
	}

	// Fetch roles and permissions for subject (== ClientID for client_credentials).
	// Non-fatal: issue token without RBAC claims rather than failing the grant.
	var roles, permissions []string
	if s.permsFetcher != nil {
		roles, permissions, _ = s.permsFetcher.GetSubjectPermissions(ctx, req.ClientID)
	}

	now := time.Now()
	raw, err := s.issueAccessToken(ctx, req.ClientID, scopes, roles, permissions, now)
	if err != nil {
		return nil, err
	}

	refreshRaw, err := s.issueRefreshToken(ctx, req.ClientID, scopes, now)
	if err != nil {
		return nil, err
	}

	return &domain.GrantResponse{
		AccessToken:  raw,
		TokenType:    "bearer",
		ExpiresIn:    int(s.ttl.Seconds()),
		RefreshToken: refreshRaw,
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// RefreshTokenStrategy handles the refresh_token grant per RFC 6749 §6.
// Issues a new access token and rotates the refresh token (old one is deleted).
type RefreshTokenStrategy struct {
	clientAuth       ports.ClientAuthenticator
	tokenRepo        domain.TokenRepository
	refreshTokenRepo domain.RefreshTokenRepository
	tokenGen         TokenGenerator
	permsFetcher     ports.SubjectPermissionsFetcher
	ttl              time.Duration
	refreshTTL       time.Duration
}

// NewRefreshTokenStrategy creates a RefreshTokenStrategy.
// permsFetcher may be nil — when nil, the re-issued token carries the same scopes
// as the original refresh token but no RBAC claims.
func NewRefreshTokenStrategy(
	clientAuth ports.ClientAuthenticator,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	permsFetcher ports.SubjectPermissionsFetcher,
	ttl time.Duration,
	refreshTTL time.Duration,
) *RefreshTokenStrategy {
	return &RefreshTokenStrategy{
		clientAuth:       clientAuth,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		permsFetcher:     permsFetcher,
		ttl:              ttl,
		refreshTTL:       refreshTTL,
	}
}

// Supports reports whether this strategy handles the refresh_token grant type.
func (s *RefreshTokenStrategy) Supports(grantType domain.GrantType) bool {
	return grantType == domain.GrantTypeRefreshToken
}

// checkExpiry returns ErrCodeUnauthorized when the refresh token is expired,
// deleting it from the store first. Returns nil when the token is still valid.
// Extracted from validateRefreshToken to keep its cyclomatic complexity within bounds.
func (s *RefreshTokenStrategy) checkExpiry(ctx context.Context, raw string, rt *domain.RefreshToken) error {
	if !time.Now().After(rt.ExpiresAt) {
		return nil
	}
	// Clean up the expired token; ignore not-found; surface other infra errors.
	if err := s.refreshTokenRepo.Delete(ctx, raw); err != nil && !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "deleting expired refresh token", err)
	}
	return apperrors.New(apperrors.ErrCodeUnauthorized, "refresh token expired")
}

// validateRefreshToken authenticates the client, looks up the refresh token, and
// validates ownership and expiry. Extracted from Handle to keep complexity bounded.
func (s *RefreshTokenStrategy) validateRefreshToken(ctx context.Context, req domain.GrantRequest) (*domain.RefreshToken, error) {
	if _, err := s.clientAuth.Authenticate(ctx, req.ClientID, req.ClientSecret); err != nil {
		return nil, fmt.Errorf("authenticating client: %w", err)
	}

	existing, err := s.refreshTokenRepo.FindByRaw(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenNotFound) {
			return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid refresh token")
		}
		return nil, fmt.Errorf("finding refresh token: %w", err)
	}

	if existing.ClientID != req.ClientID {
		return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "refresh token was not issued to this client")
	}

	if err := s.checkExpiry(ctx, req.RefreshToken, existing); err != nil {
		return nil, err
	}

	return existing, nil
}

// rotateRefreshToken deletes the old refresh token and issues a new one.
// Extracted from Handle to keep complexity bounded.
func (s *RefreshTokenStrategy) rotateRefreshToken(ctx context.Context, oldRaw string, existing *domain.RefreshToken, now time.Time) (string, error) {
	if err := s.refreshTokenRepo.Delete(ctx, oldRaw); err != nil && !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		return "", fmt.Errorf("rotating refresh token: %w", err)
	}

	newRefreshRaw, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token value", err)
	}
	newRefreshID, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token id", err)
	}
	newRefresh := &domain.RefreshToken{
		ID:        newRefreshID,
		Raw:       newRefreshRaw,
		ClientID:  existing.ClientID,
		Subject:   existing.Subject,
		Scopes:    existing.Scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.refreshTTL),
	}
	if err := s.refreshTokenRepo.Save(ctx, newRefresh); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "saving rotated refresh token", err)
	}
	return newRefreshRaw, nil
}

// Handle processes a refresh_token grant request.
// Validates the client and refresh token, issues a new access token with updated
// RBAC claims, and rotates the refresh token.
func (s *RefreshTokenStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	existing, err := s.validateRefreshToken(ctx, req)
	if err != nil {
		return nil, err
	}

	// Fetch updated roles and permissions for the subject.
	// Non-fatal: issue token without RBAC claims if the policy service is unavailable.
	var roles, permissions []string
	if s.permsFetcher != nil {
		roles, permissions, _ = s.permsFetcher.GetSubjectPermissions(ctx, existing.Subject)
	}

	now := time.Now()
	id, err := generateID()
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "generating token id", err)
	}
	token := &domain.Token{
		ID:          id,
		ClientID:    existing.ClientID,
		Subject:     existing.Subject,
		Scopes:      existing.Scopes,
		Roles:       roles,
		Permissions: permissions,
		ExpiresAt:   now.Add(s.ttl),
		IssuedAt:    now,
		TokenType:   domain.TokenTypeBearer,
	}
	raw, err := s.tokenGen.Generate(ctx, token)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "generating access token", err)
	}
	token.Raw = raw
	if err := s.tokenRepo.Save(ctx, token); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "saving access token", err)
	}

	newRefreshRaw, err := s.rotateRefreshToken(ctx, req.RefreshToken, existing, now)
	if err != nil {
		return nil, err
	}

	return &domain.GrantResponse{
		AccessToken:  raw,
		TokenType:    "bearer",
		ExpiresIn:    int(s.ttl.Seconds()),
		RefreshToken: newRefreshRaw,
		Scope:        strings.Join(existing.Scopes, " "),
	}, nil
}

// AuthorizationCodeStrategy handles the authorization_code grant.
// The UserAuthenticator field wires in identity-service for user credential
// verification; the full code-exchange flow (PKCE, redirect URI validation,
// code issuance) is not yet implemented.
type AuthorizationCodeStrategy struct {
	clientRepo domain.ClientRepository
	tokenRepo  domain.TokenRepository
	tokenGen   TokenGenerator
	ttl        time.Duration
	userAuth   ports.UserAuthenticator // nil when identity-service URL is not configured
}

// NewAuthorizationCodeStrategy creates an AuthorizationCodeStrategy.
// userAuth may be nil — the grant remains a stub until the full flow is implemented.
func NewAuthorizationCodeStrategy(
	clientRepo domain.ClientRepository,
	tokenRepo domain.TokenRepository,
	tokenGen TokenGenerator,
	ttl time.Duration,
	userAuth ports.UserAuthenticator,
) *AuthorizationCodeStrategy {
	return &AuthorizationCodeStrategy{
		clientRepo: clientRepo,
		tokenRepo:  tokenRepo,
		tokenGen:   tokenGen,
		ttl:        ttl,
		userAuth:   userAuth,
	}
}

// Supports reports whether this strategy handles the authorization_code grant type.
func (s *AuthorizationCodeStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeAuthorizationCode
}

// Handle is a stub. When userAuth is wired, it validates user credentials as
// the first step. Full PKCE / code-exchange flow is not yet implemented.
func (s *AuthorizationCodeStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	if s.userAuth != nil {
		// Validate user credentials — the first step of the authorization_code flow.
		// The rest of the flow (code issuance, PKCE, redirect URI check) is not yet implemented.
		if _, err := s.userAuth.VerifyCredentials(ctx, req.Username, req.Password); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: %s is not yet fully implemented", ErrUnsupportedGrantType, req.GrantType)
}
