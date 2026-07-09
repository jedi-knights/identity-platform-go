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
	"github.com/jedi-knights/go-platform/audit"
	"github.com/jedi-knights/go-platform/jwtutil"

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

// authenticateClient resolves the calling client via either a
// client_secret (the default) or an RFC 7523 JWT-bearer assertion
// (ADR-0023). Shared by every strategy that supports both, so the
// dispatch rule lives in one place. A GrantRequest carrying a non-empty
// ClientAssertion always uses the assertion path — there is no fallback
// to ClientSecret once a client presents one. assertionAuth may be nil
// (JWT-bearer support not wired for this strategy or deployment); a
// request presenting an assertion in that case is rejected rather than
// silently falling back to secret-based auth.
func authenticateClient(ctx context.Context, secretAuth ports.ClientAuthenticator, assertionAuth *ClientAssertionValidator, req domain.GrantRequest) (*domain.Client, error) {
	if req.ClientAssertion != "" {
		if assertionAuth == nil {
			return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "client assertion authentication is not configured")
		}
		return assertionAuth.Authenticate(ctx, req.ClientID, req.ClientAssertion)
	}
	return secretAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)
}

// GrantStrategy defines the interface for handling grant types (Strategy pattern).
type GrantStrategy interface {
	Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error)
	Supports(gt domain.GrantType) bool
}

// GrantStrategyRegistry holds all grant strategies (Registry/Factory pattern).
//
// The registry is the chokepoint for token issuance and therefore the
// natural emission point for the ADR-0018 token_issued audit event.
// Emission is wired via [GrantStrategyRegistry.WithAudit]; when audit is
// not configured the registry uses a no-op emitter that always succeeds,
// preserving backwards compatibility for tests and adapters that pre-date
// the audit feature.
type GrantStrategyRegistry struct {
	strategies []GrantStrategy

	// emitter is the audit.Emitter used by Handle on successful token
	// issuance. Defaults to noopEmitter so unwired callers keep working.
	emitter audit.Emitter
	// service is the value placed on Event.Service. Defaults to
	// "auth-server" which is correct for the only deployment of this
	// registry today.
	service string
}

// NewGrantStrategyRegistry creates a registry containing all provided strategies.
// The registry defaults to a no-op audit emitter; call [GrantStrategyRegistry.WithAudit]
// to wire a real emitter at composition time.
func NewGrantStrategyRegistry(strategies ...GrantStrategy) *GrantStrategyRegistry {
	return &GrantStrategyRegistry{
		strategies: strategies,
		emitter:    audit.New(audit.NoopSink{}),
		service:    "auth-server",
	}
}

// WithAudit configures the registry's audit emitter and service name.
// Returns the receiver to allow chained construction at the composition
// root. emitter must be non-nil; service is used as Event.Service on
// every emitted token_issued event.
//
// Per ADR-0019 the durable-sink failure must fail token issuance for
// paid event types — the registry returns the audit error to the caller
// when Emit fails, which propagates as a 500 from the token endpoint
// (callers retry; the prior token's TTL prevents accumulation).
func (r *GrantStrategyRegistry) WithAudit(emitter audit.Emitter, service string) *GrantStrategyRegistry {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	r.emitter = emitter
	if service != "" {
		r.service = service
	}
	return r
}

// Handle dispatches the grant request to the first matching strategy
// and emits a token_issued audit event on success. Returns
// ErrUnsupportedGrantType when no strategy supports the grant type.
//
// On a successful strategy invocation the registry calls audit.Emit
// before returning the token to the caller. An emission error is
// surfaced to the caller — see [WithAudit] for the rationale.
func (r *GrantStrategyRegistry) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	for _, s := range r.strategies {
		if !s.Supports(req.GrantType) {
			continue
		}
		resp, err := s.Handle(ctx, req)
		if err != nil {
			return nil, err
		}
		if emitErr := r.emitter.Emit(ctx, tokenIssuedEvent(r.service, req, resp)); emitErr != nil {
			return nil, fmt.Errorf("audit emit (token_issued): %w", emitErr)
		}
		return resp, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedGrantType, req.GrantType)
}

// tokenIssuedEvent constructs the ADR-0018 envelope for a successful
// token grant. ActorType / actor_id are sourced from the grant's
// authenticated principal via the server-internal fields the strategy
// stamped onto [domain.GrantResponse] (ActorType, AgentID, Subject):
//   - For client_credentials and refresh_token grants the actor is the
//     OAuth client itself, classified by [domain.Client.ResolvedActorType].
//   - For authorization_code the actor is the human resource owner; the
//     client's classification is recorded as an attr but not as the
//     envelope's actor_type, matching ADR-0015's "user owns the cost"
//     default in identity-platform-go ADR-0019.
func tokenIssuedEvent(service string, req domain.GrantRequest, resp *domain.GrantResponse) audit.Event {
	actorType := audit.ActorType(resp.ActorType)
	if actorType == "" {
		actorType = audit.ActorTypeService
	}
	actorID := req.ClientID
	if resp.ActorType == domain.ActorTypeUser {
		actorID = resp.Subject
	}
	attrs := map[string]any{
		"grant_type":  string(req.GrantType),
		"scope":       resp.Scope,
		"expires_in":  resp.ExpiresIn,
		"id_token":    resp.IDToken != "",
		"has_refresh": resp.RefreshToken != "",
		"actor_type":  string(resp.ActorType),
	}
	if resp.AgentID != "" {
		attrs["agent_id"] = resp.AgentID
	}
	return audit.Event{
		EventType:      "token_issued",
		Service:        service,
		ActorType:      actorType,
		ActorID:        actorID,
		SubjectID:      resp.Subject,
		ClientID:       req.ClientID,
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: service,
		ResourcePath:   service + "/token/access",
		Action:         "issue",
		Decision:       audit.DecisionAllow,
		Attrs:          attrs,
	}
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
	// assertionAuth handles RFC 7523 JWT-bearer client authentication
	// (ADR-0023) when the request carries a client_assertion. Nil =
	// JWT-bearer support not wired; such a request is then rejected
	// rather than silently falling back to client_secret.
	assertionAuth *ClientAssertionValidator
}

// NewClientCredentialsStrategy creates a ClientCredentialsStrategy.
// permsFetcher may be nil — when nil, tokens are issued without roles/permissions claims.
// assertionAuth may be nil — when nil, this strategy accepts client_secret only.
func NewClientCredentialsStrategy(
	clientAuth ports.ClientAuthenticator,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	permsFetcher ports.SubjectPermissionsFetcher,
	ttl time.Duration,
	refreshTTL time.Duration,
	assertionAuth *ClientAssertionValidator,
) *ClientCredentialsStrategy {
	return &ClientCredentialsStrategy{
		clientAuth:       clientAuth,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		permsFetcher:     permsFetcher,
		ttl:              ttl,
		refreshTTL:       refreshTTL,
		assertionAuth:    assertionAuth,
	}
}

// Supports reports whether this strategy handles the given grant type.
func (s *ClientCredentialsStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeClientCredentials
}

func (s *ClientCredentialsStrategy) validateClient(ctx context.Context, req domain.GrantRequest) (*domain.Client, error) {
	client, err := authenticateClient(ctx, s.clientAuth, s.assertionAuth, req)
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
func (s *ClientCredentialsStrategy) issueAccessToken(ctx context.Context, client *domain.Client, scopes, roles, permissions []string, now time.Time, authzDetails []domain.AuthorizationDetail) (string, error) {
	tokenID, err := generateID()
	if err != nil {
		return "", apperrors.Wrap(apperrors.ErrCodeInternal, "generating token id", err)
	}
	token := &domain.Token{
		ID:                   tokenID,
		ClientID:             client.ID,
		Subject:              client.ID,
		Scopes:               scopes,
		Roles:                roles,
		Permissions:          permissions,
		ActorType:            client.ResolvedActorType(),
		AgentID:              client.AgentID(),
		AuthorizationDetails: authzDetails,
		ExpiresAt:            now.Add(s.ttl),
		IssuedAt:             now,
		TokenType:            domain.TokenTypeBearer,
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
	raw, err := s.issueAccessToken(ctx, client, scopes, roles, permissions, now, req.AuthorizationDetails)
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
		ActorType:    client.ResolvedActorType(),
		AgentID:      client.AgentID(),
		Subject:      client.ID,
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
	// assertionAuth handles RFC 7523 JWT-bearer client authentication
	// (ADR-0023) when the request carries a client_assertion. Nil = not
	// wired; such a request is then rejected.
	assertionAuth *ClientAssertionValidator
}

// NewRefreshTokenStrategy creates a RefreshTokenStrategy.
// permsFetcher may be nil — when nil, the re-issued token carries the same scopes
// as the original refresh token but no RBAC claims. assertionAuth may be
// nil — when nil, this strategy accepts client_secret only.
func NewRefreshTokenStrategy(
	clientAuth ports.ClientAuthenticator,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	permsFetcher ports.SubjectPermissionsFetcher,
	ttl time.Duration,
	refreshTTL time.Duration,
	assertionAuth *ClientAssertionValidator,
) *RefreshTokenStrategy {
	return &RefreshTokenStrategy{
		clientAuth:       clientAuth,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		permsFetcher:     permsFetcher,
		ttl:              ttl,
		refreshTTL:       refreshTTL,
		assertionAuth:    assertionAuth,
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
// validates ownership and expiry. Returns the authenticated client alongside
// the refresh token so the caller can propagate ActorType / AgentID claims
// (ADR-0015) onto the rotated access token. Extracted from Handle to keep
// complexity bounded.
func (s *RefreshTokenStrategy) validateRefreshToken(ctx context.Context, req domain.GrantRequest) (*domain.RefreshToken, *domain.Client, error) {
	client, err := authenticateClient(ctx, s.clientAuth, s.assertionAuth, req)
	if err != nil {
		return nil, nil, fmt.Errorf("authenticating client: %w", err)
	}

	existing, err := s.refreshTokenRepo.FindByRaw(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenNotFound) {
			return nil, nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid refresh token")
		}
		return nil, nil, fmt.Errorf("finding refresh token: %w", err)
	}

	if existing.ClientID != req.ClientID {
		return nil, nil, apperrors.New(apperrors.ErrCodeUnauthorized, "refresh token was not issued to this client")
	}

	if err := s.checkExpiry(ctx, req.RefreshToken, existing); err != nil {
		return nil, nil, err
	}

	return existing, client, nil
}

// refreshActorClassification derives ActorType + AgentID for a rotated
// access token. The original refresh token does not carry actor_type
// directly, but its Subject vs ClientID relationship tells us which grant
// originally produced it:
//   - Subject == ClientID → originally minted via client_credentials, so
//     the token represents the client itself. ActorType comes from the
//     client record (service or agent per ADR-0015).
//   - Subject != ClientID → originally minted via authorization_code, so
//     the token represents the human resource owner. ActorType is "user"
//     regardless of the refreshing client's classification.
func refreshActorClassification(rt *domain.RefreshToken, client *domain.Client) (domain.ActorType, string) {
	if rt.Subject == rt.ClientID {
		return client.ResolvedActorType(), client.AgentID()
	}
	return domain.ActorTypeUser, ""
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
	existing, client, err := s.validateRefreshToken(ctx, req)
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
	actorType, agentID := refreshActorClassification(existing, client)
	token := &domain.Token{
		ID:          id,
		ClientID:    existing.ClientID,
		Subject:     existing.Subject,
		Scopes:      existing.Scopes,
		Roles:       roles,
		Permissions: permissions,
		ActorType:   actorType,
		AgentID:     agentID,
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
		ActorType:    actorType,
		AgentID:      agentID,
		Subject:      existing.Subject,
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
	claimsFetcher    ports.UserClaimsFetcher         // nil = no profile/email claims in ID token
	idTokenGen       *IDTokenGenerator               // nil = no OIDC mode (HS256 fallback)
	ttl              time.Duration
	refreshTTL       time.Duration
	idTokenTTL       time.Duration
	// assertionAuth handles RFC 7523 JWT-bearer client authentication
	// (ADR-0023) when the request carries a client_assertion. Nil = not
	// wired; such a request is then rejected.
	assertionAuth *ClientAssertionValidator
}

// NewAuthorizationCodeStrategy wires the strategy with every collaborator
// the 12-step pipeline and token issuance need. permsFetcher may be nil —
// tokens are then issued without Roles / Permissions claims, matching the
// existing client_credentials behaviour. claimsFetcher and idTokenGen may
// be nil — the openid scope is then silently dropped from the response and
// no id_token is issued, matching the legacy OAuth-only behaviour.
// assertionAuth may be nil — when nil, this strategy accepts client_secret
// only.
func NewAuthorizationCodeStrategy(
	clientAuth ports.ClientAuthenticator,
	codeRepo domain.AuthorizationCodeRepository,
	tokenRepo domain.TokenRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	tokenGen TokenGenerator,
	permsFetcher ports.SubjectPermissionsFetcher,
	claimsFetcher ports.UserClaimsFetcher,
	idTokenGen *IDTokenGenerator,
	ttl, refreshTTL, idTokenTTL time.Duration,
	assertionAuth *ClientAssertionValidator,
) *AuthorizationCodeStrategy {
	return &AuthorizationCodeStrategy{
		clientAuth:       clientAuth,
		codeRepo:         codeRepo,
		tokenRepo:        tokenRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGen:         tokenGen,
		permsFetcher:     permsFetcher,
		claimsFetcher:    claimsFetcher,
		idTokenGen:       idTokenGen,
		ttl:              ttl,
		refreshTTL:       refreshTTL,
		idTokenTTL:       idTokenTTL,
		assertionAuth:    assertionAuth,
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
	client, err := authenticateClient(ctx, s.clientAuth, s.assertionAuth, req)
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
		// ADR-0015: authorization_code tokens represent the human resource
		// owner regardless of the client's own ActorType. The client may be
		// an agent acting on the user's behalf, but the access token still
		// carries the user's identity.
		ActorType: domain.ActorTypeUser,
		// ADR-0017: the granted authorization_details follow the code
		// onto the token so RAR-aware resource servers see the same
		// per-call permissions the user approved at /oauth/authorize.
		AuthorizationDetails: code.AuthorizationDetails,
		ExpiresAt:            now.Add(s.ttl),
		IssuedAt:             now,
		TokenType:            domain.TokenTypeBearer,
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
	idToken, err := s.maybeIssueIDToken(ctx, client.ID, code, raw, now)
	if err != nil {
		return nil, err
	}
	return &domain.GrantResponse{
		AccessToken:  raw,
		IDToken:      idToken,
		TokenType:    string(domain.TokenTypeBearer),
		ExpiresIn:    int(s.ttl.Seconds()),
		RefreshToken: refreshRaw,
		Scope:        strings.Join(code.Scopes, " "),
		ActorType:    domain.ActorTypeUser,
		Subject:      code.Subject,
	}, nil
}

// maybeIssueIDToken returns the OIDC ID token when the code's scope set
// includes "openid" and the strategy was wired with an IDTokenGenerator
// (i.e. RS256 mode + AUTH_OIDC_ISSUER set). Returns "" with no error in
// every other case — the OAuth-only flow keeps its current response shape.
//
// at_hash is computed against the FINAL signed access token (rawAccessToken),
// per OIDC §3.1.3.6 and the binding rule from ADR-0010's review fixes.
func (s *AuthorizationCodeStrategy) maybeIssueIDToken(ctx context.Context, clientID string, code *domain.AuthorizationCode, rawAccessToken string, now time.Time) (string, error) {
	if s.idTokenGen == nil || !domain.HasScope(code.Scopes, domain.ScopeOpenID) {
		return "", nil
	}
	issuance := IDTokenIssuance{
		Subject:   code.Subject,
		Audience:  clientID,
		Nonce:     code.Nonce,
		AtHash:    jwtutil.AtHash(rawAccessToken),
		AuthTime:  code.IssuedAt,
		AMR:       []string{"pwd"},
		IssuedAt:  now,
		ExpiresAt: now.Add(s.idTokenTTL),
	}
	s.populateProfileClaims(ctx, code, &issuance)
	return s.idTokenGen.Generate(ctx, issuance)
}

// populateProfileClaims fetches user claims when the scope set requests them
// and copies the permitted fields onto the ID-token issuance request. Claim
// filtering by scope happens here so the generator stays format-only.
//
// Failure to fetch claims is non-fatal — the token issues without those
// fields, matching the same fallback used for permissions.
func (s *AuthorizationCodeStrategy) populateProfileClaims(ctx context.Context, code *domain.AuthorizationCode, issuance *IDTokenIssuance) {
	wantsEmail, wantsProfile, shouldFetch := s.shouldFetchUserClaims(code.Scopes)
	if !shouldFetch {
		return
	}
	claims := s.fetchProfileClaims(ctx, code.Subject)
	if claims == nil {
		return
	}
	if wantsEmail {
		applyEmailClaims(issuance, claims)
	}
	if wantsProfile {
		applyProfileClaims(issuance, claims)
	}
}

// shouldFetchUserClaims tells populateProfileClaims whether to bother
// calling the fetcher at all. Returns (wantsEmail, wantsProfile, ok) where
// ok is false when the fetcher is unwired or neither claim subset was
// requested. Folded out so populateProfileClaims keeps a single
// straight-line branch budget.
func (s *AuthorizationCodeStrategy) shouldFetchUserClaims(scopes []string) (wantsEmail, wantsProfile, ok bool) {
	if s.claimsFetcher == nil {
		return false, false, false
	}
	wantsEmail = domain.HasScope(scopes, domain.ScopeEmail)
	wantsProfile = domain.HasScope(scopes, domain.ScopeProfile)
	return wantsEmail, wantsProfile, wantsEmail || wantsProfile
}

// fetchProfileClaims wraps the fetcher call and translates the (claims,
// err) tuple into a single nilable return so the caller's branch count
// drops by one. Failure remains non-fatal — the token still issues.
func (s *AuthorizationCodeStrategy) fetchProfileClaims(ctx context.Context, subject string) *ports.UserClaims {
	claims, err := s.claimsFetcher.GetUserClaims(ctx, subject)
	if err != nil {
		return nil
	}
	return claims
}

// applyEmailClaims copies the email/email_verified fields onto issuance.
// EmailVerified is dereferenced to a local then re-addressed so the on-the-
// wire claim distinguishes "we don't know" (nil) from "explicitly false"
// (&false); the OIDC IDClaims type is *bool for that reason.
func applyEmailClaims(issuance *IDTokenIssuance, claims *ports.UserClaims) {
	issuance.Email = claims.Email
	ev := claims.EmailVerified
	issuance.EmailVerified = &ev
}

// applyProfileClaims copies name and updated_at onto issuance, converting
// the Unix-seconds wire value to time.Time so the generator can format it
// uniformly with other date claims.
func applyProfileClaims(issuance *IDTokenIssuance, claims *ports.UserClaims) {
	issuance.Name = claims.Name
	if claims.UpdatedAt > 0 {
		issuance.UpdatedAt = time.Unix(claims.UpdatedAt, 0)
	}
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
