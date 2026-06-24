package application

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// ErrUnsupportedGrantType is returned when the requested grant type has no registered strategy.
var ErrUnsupportedGrantType = errors.New("unsupported grant type")

// Token-endpoint error sentinels. Each maps to the matching RFC 6749 §5.2
// error code at the HTTP layer (writeTokenError). They are package-level
// values so the strategy can return them via fmt.Errorf("%w: ...", Err…)
// and the handler can distinguish them via errors.Is.
var (
	// ErrInvalidRequest — missing or malformed parameter at the token
	// endpoint (RFC 6749 §5.2 "invalid_request").
	ErrInvalidRequest = errors.New("invalid_request")

	// ErrInvalidGrant — the authorization code, refresh token, or PKCE
	// verifier presented is not valid for any reason (RFC 6749 §5.2
	// "invalid_grant"). The granularity is deliberately coarse so a caller
	// cannot distinguish "wrong code_verifier" from "wrong redirect_uri" —
	// that distinction would help attackers narrow down what they're missing.
	ErrInvalidGrant = errors.New("invalid_grant")

	// ErrUnauthorizedClient — the client is authenticated but is not
	// allowed to use this grant type (RFC 6749 §5.2 "unauthorized_client").
	ErrUnauthorizedClient = errors.New("unauthorized_client")
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
		TokenType:    string(domain.TokenTypeBearer),
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
		TokenType:    string(domain.TokenTypeBearer),
		ExpiresIn:    int(s.ttl.Seconds()),
		RefreshToken: newRefreshRaw,
		Scope:        strings.Join(existing.Scopes, " "),
	}, nil
}

// AuthorizationCodeStrategy implements the OAuth 2.1 authorization_code grant
// per ADR-0009. The Handle method runs the 12-step validation pipeline (form
// fields, client auth, grant-type allowance, atomic code consumption, code-
// to-request consistency, expiry, PKCE method, S256 verifier) and then
// issues an access token and refresh token via the shared TokenGenerator
// and repositories.
//
// PKCE is mandatory and S256-only. Public clients (no secret) are accepted
// when the client's stored Secret matches the presented (typically empty)
// value — the constant-time comparison in the ClientAuthenticator handles
// both confidential and public clients uniformly.
type AuthorizationCodeStrategy struct {
	clientAuth       ports.ClientAuthenticator
	codeRepo         domain.AuthorizationCodeRepository
	tokenRepo        domain.TokenRepository
	refreshTokenRepo domain.RefreshTokenRepository
	tokenGen         TokenGenerator
	permsFetcher     ports.SubjectPermissionsFetcher // nil = no RBAC claims
	ttl              time.Duration
	refreshTTL       time.Duration
}

// NewAuthorizationCodeStrategy wires the strategy with every collaborator
// the 12-step pipeline and token issuance need. permsFetcher may be nil —
// tokens are then issued without Roles / Permissions claims, matching the
// existing client_credentials behaviour.
func NewAuthorizationCodeStrategy(
	clientAuth ports.ClientAuthenticator,
	codeRepo domain.AuthorizationCodeRepository,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	permsFetcher ports.SubjectPermissionsFetcher,
	ttl, refreshTTL time.Duration,
) *AuthorizationCodeStrategy {
	return &AuthorizationCodeStrategy{
		clientAuth:       clientAuth,
		codeRepo:         codeRepo,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		permsFetcher:     permsFetcher,
		ttl:              ttl,
		refreshTTL:       refreshTTL,
	}
}

// Supports reports whether this strategy handles the authorization_code grant type.
func (s *AuthorizationCodeStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeAuthorizationCode
}

// Handle runs the ADR-0009 token-endpoint validation pipeline and, on
// success, issues access + refresh tokens. The order is load-bearing —
// authentication before code lookup so an unauthenticated probe cannot
// learn whether a code exists; consume before any value comparison so the
// "wrong client_id" path also cleans up the code.
func (s *AuthorizationCodeStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	if err := validateAuthCodeRequestFields(req); err != nil {
		return nil, err
	}
	client, err := s.clientAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !client.HasGrantType(domain.GrantTypeAuthorizationCode) {
		return nil, fmt.Errorf("%w: grant type not allowed for client", ErrUnauthorizedClient)
	}
	code, err := s.codeRepo.Consume(ctx, req.Code)
	if err != nil {
		if errors.Is(err, domain.ErrAuthorizationCodeNotFound) {
			return nil, fmt.Errorf("%w: code unknown, expired, or already consumed", ErrInvalidGrant)
		}
		return nil, fmt.Errorf("consuming authorization code: %w", err)
	}
	if err := verifyAuthCodeMatchesRequest(code, req); err != nil {
		return nil, err
	}
	return s.issueTokens(ctx, client, code)
}

// validateAuthCodeRequestFields checks the form fields that must be present
// before any further work — RFC 6749 §5.2 "invalid_request".
func validateAuthCodeRequestFields(req domain.GrantRequest) error {
	switch {
	case req.Code == "":
		return fmt.Errorf("%w: code is required", ErrInvalidRequest)
	case req.RedirectURI == "":
		return fmt.Errorf("%w: redirect_uri is required", ErrInvalidRequest)
	case req.CodeVerifier == "":
		// PKCE is mandatory per ADR-0009 — every client, every flow.
		return fmt.Errorf("%w: code_verifier is required", ErrInvalidRequest)
	}
	return nil
}

// verifyAuthCodeMatchesRequest cross-checks the stored code against the
// request that presented it: client_id binding, redirect_uri byte-exact
// match, expiry, PKCE method, and the S256 verifier comparison itself. The
// expiry check is defense-in-depth — the repository's Consume also drops
// expired entries — but the strategy's expiry view is the canonical one.
func verifyAuthCodeMatchesRequest(code *domain.AuthorizationCode, req domain.GrantRequest) error {
	if code.ClientID != req.ClientID {
		return fmt.Errorf("%w: code was issued to a different client", ErrInvalidGrant)
	}
	if code.RedirectURI != req.RedirectURI {
		return fmt.Errorf("%w: redirect_uri does not match the value presented at /oauth/authorize", ErrInvalidGrant)
	}
	if code.IsExpiredAt(time.Now()) {
		return fmt.Errorf("%w: code expired", ErrInvalidGrant)
	}
	if !code.HasValidPKCEMethod() {
		return fmt.Errorf("%w: code_challenge_method must be S256", ErrInvalidGrant)
	}
	if !verifyPKCES256(req.CodeVerifier, code.CodeChallenge) {
		return fmt.Errorf("%w: code_verifier does not match code_challenge", ErrInvalidGrant)
	}
	return nil
}

// verifyPKCES256 hashes the verifier with SHA-256, base64url-encodes the
// digest, and compares against the stored challenge in constant time. RFC
// 7636 §4.6 — the comparison MUST be constant-time so a timing oracle does
// not reveal partial-match information.
func verifyPKCES256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// issueTokens mints the access token + refresh token after every validation
// has passed. The shape mirrors ClientCredentialsStrategy's issuance path
// (RBAC fetch is optional; refresh token is opaque hex). Failure to fetch
// permissions does NOT fail the flow — tokens issue without RBAC claims, the
// same fallback ClientCredentialsStrategy uses.
func (s *AuthorizationCodeStrategy) issueTokens(ctx context.Context, client *domain.Client, code *domain.AuthorizationCode) (*domain.GrantResponse, error) {
	var roles, permissions []string
	if s.permsFetcher != nil {
		roles, permissions, _ = s.permsFetcher.GetSubjectPermissions(ctx, code.Subject)
	}
	now := time.Now()
	tokenID, err := generateID()
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "generating token id", err)
	}
	token := &domain.Token{
		ID:          tokenID,
		ClientID:    client.ID,
		Subject:     code.Subject,
		Scopes:      code.Scopes,
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
	refreshRaw, err := s.issueAuthCodeRefreshToken(ctx, client.ID, code, now)
	if err != nil {
		return nil, err
	}
	return &domain.GrantResponse{
		AccessToken:  raw,
		TokenType:    string(domain.TokenTypeBearer),
		ExpiresIn:    int(s.ttl.Seconds()),
		RefreshToken: refreshRaw,
		Scope:        strings.Join(code.Scopes, " "),
	}, nil
}

// issueAuthCodeRefreshToken generates and persists a fresh opaque refresh
// token bound to the subject from the authorization code. Mirrors the
// ClientCredentialsStrategy.issueRefreshToken pattern.
func (s *AuthorizationCodeStrategy) issueAuthCodeRefreshToken(ctx context.Context, clientID string, code *domain.AuthorizationCode, now time.Time) (string, error) {
	raw, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token raw value", err)
	}
	id, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating refresh token id", err)
	}
	rt := &domain.RefreshToken{
		ID:        id,
		Raw:       raw,
		ClientID:  clientID,
		Subject:   code.Subject,
		Scopes:    code.Scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.refreshTTL),
	}
	if err := s.refreshTokenRepo.Save(ctx, rt); err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "saving refresh token", err)
	}
	return raw, nil
}
