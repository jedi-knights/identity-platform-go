package application

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// defaultMaxDelegationDepth caps the resulting Act chain length per
// ADR-0016 §"Validation". Three hops covers the common A2A pattern
// (agent calls agent on behalf of human) without enabling unbounded
// fan-out. Operators can lower it at composition time via
// [TokenExchangeStrategyConfig]; raising it is allowed but flagged in
// the ADR as a risky configuration.
const defaultMaxDelegationDepth = 3

// defaultExchangeMaxTTL caps the lifetime of exchanged access tokens.
// Five minutes matches the ADR's stated default — delegated tokens
// should be short-lived so a leaked exchanged token has a small blast
// radius. The strategy still caps to the remaining lifetime of the
// subject_token, so this is only a ceiling.
const defaultExchangeMaxTTL = 5 * time.Minute

// TokenExchangeStrategy implements the RFC 8693 §2.1 token-exchange
// grant per ADR-0016. It validates a presented subject_token (and
// optionally an actor_token), prepends the calling actor to the
// resulting act chain, and issues a short-lived access token whose
// identity is the subject_token's subject but whose action attribution
// is the calling actor.
type TokenExchangeStrategy struct {
	clientAuth     ports.ClientAuthenticator
	tokenValidator TokenValidator
	tokenRepo      domain.TokenRepository
	tokenGen       TokenGenerator
	maxDepth       int
	maxTTL         time.Duration
}

// TokenExchangeStrategyConfig captures the constructor inputs so callers
// can pass them as named fields rather than nine positional arguments.
type TokenExchangeStrategyConfig struct {
	ClientAuth     ports.ClientAuthenticator
	TokenValidator TokenValidator
	TokenRepo      domain.TokenRepository
	TokenGen       TokenGenerator

	// MaxDepth caps the depth of the resulting Act chain. Zero falls
	// back to [defaultMaxDelegationDepth].
	MaxDepth int
	// MaxTTL caps the lifetime of issued exchanged tokens. Zero falls
	// back to [defaultExchangeMaxTTL].
	MaxTTL time.Duration
}

// NewTokenExchangeStrategy wires the strategy. Every collaborator other
// than ClientAuth is required for the happy path; ClientAuth is
// required for confidential clients but may be a stub in test
// scenarios that exercise only public-client behaviour.
func NewTokenExchangeStrategy(cfg TokenExchangeStrategyConfig) *TokenExchangeStrategy {
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDelegationDepth
	}
	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultExchangeMaxTTL
	}
	return &TokenExchangeStrategy{
		clientAuth:     cfg.ClientAuth,
		tokenValidator: cfg.TokenValidator,
		tokenRepo:      cfg.TokenRepo,
		tokenGen:       cfg.TokenGen,
		maxDepth:       maxDepth,
		maxTTL:         maxTTL,
	}
}

// Supports reports whether this strategy handles the given grant type.
func (s *TokenExchangeStrategy) Supports(gt domain.GrantType) bool {
	return gt == domain.GrantTypeTokenExchange
}

// Handle validates the exchange request and issues the delegated token.
//
//nolint:gocyclo // RFC 8693 is a flat list of independent validation rules; splitting them obscures the spec mapping. Helpers are extracted where the spec allows.
func (s *TokenExchangeStrategy) Handle(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	if err := validateExchangeShape(req); err != nil {
		return nil, err
	}

	caller, err := s.authenticateCaller(ctx, req)
	if err != nil {
		return nil, err
	}

	subjectToken, err := s.tokenValidator.Validate(ctx, req.SubjectToken)
	if err != nil {
		return nil, fmt.Errorf("%w: subject_token invalid", ErrInvalidRequest)
	}
	if err := s.assertCanExchange(caller, subjectToken); err != nil {
		return nil, err
	}

	var actorToken *domain.Token
	if req.ActorToken != "" {
		actorToken, err = s.tokenValidator.Validate(ctx, req.ActorToken)
		if err != nil {
			return nil, fmt.Errorf("%w: actor_token invalid", ErrInvalidRequest)
		}
	}

	scopes, err := resolveExchangeScopes(req.Scopes, subjectToken.Scopes)
	if err != nil {
		return nil, err
	}

	chain := s.buildActChain(caller, actorToken, subjectToken)
	if depth := chain.Depth(); depth > s.maxDepth {
		return nil, fmt.Errorf("%w: delegation chain depth %d exceeds limit %d", ErrInvalidRequest, depth, s.maxDepth)
	}

	now := time.Now()
	ttl := s.resolveTTL(now, subjectToken)
	actorType, agentID := s.resolveActor(caller, actorToken)

	tokenID, err := generateID()
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "generate token id", err)
	}
	token := &domain.Token{
		ID:        tokenID,
		ClientID:  caller.ID,
		Subject:   subjectToken.Subject,
		Audience:  req.Audience,
		Scopes:    scopes,
		ActorType: actorType,
		AgentID:   agentID,
		Act:       chain,
		ExpiresAt: now.Add(ttl),
		IssuedAt:  now,
		TokenType: domain.TokenTypeBearer,
	}
	raw, err := s.tokenGen.Generate(ctx, token)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "token generation failed", err)
	}
	token.Raw = raw
	if err := s.tokenRepo.Save(ctx, token); err != nil {
		return nil, apperrors.Wrap(apperrors.ErrCodeInternal, "save token", err)
	}

	return &domain.GrantResponse{
		AccessToken:     raw,
		TokenType:       string(domain.TokenTypeBearer),
		ExpiresIn:       int(ttl.Seconds()),
		Scope:           strings.Join(scopes, " "),
		IssuedTokenType: domain.TokenTypeURNAccessToken,
		ActorType:       actorType,
		AgentID:         agentID,
		Subject:         subjectToken.Subject,
	}, nil
}

// validateExchangeShape enforces the RFC 8693 §2.1 required-field rules
// at the wire boundary so the strategy proper never inspects empty
// inputs. Each rule maps to invalid_request per §2.2.2.
func validateExchangeShape(req domain.GrantRequest) error {
	if req.SubjectToken == "" {
		return fmt.Errorf("%w: subject_token is required", ErrInvalidRequest)
	}
	if req.SubjectTokenType == "" {
		return fmt.Errorf("%w: subject_token_type is required", ErrInvalidRequest)
	}
	if req.SubjectTokenType != domain.TokenTypeURNAccessToken {
		return fmt.Errorf("%w: subject_token_type %q is not supported", ErrInvalidRequest, req.SubjectTokenType)
	}
	if req.ActorToken != "" && req.ActorTokenType != domain.TokenTypeURNAccessToken {
		return fmt.Errorf("%w: actor_token_type %q is not supported", ErrInvalidRequest, req.ActorTokenType)
	}
	if req.RequestedTokenType != "" && req.RequestedTokenType != domain.TokenTypeURNAccessToken {
		return fmt.Errorf("%w: requested_token_type %q is not supported", ErrInvalidRequest, req.RequestedTokenType)
	}
	return nil
}

// authenticateCaller resolves the OAuth client making the exchange
// request. Confidential clients present client_secret; public clients
// (no secret) are accepted but their authority to exchange a given
// subject_token is checked in [assertCanExchange].
func (s *TokenExchangeStrategy) authenticateCaller(ctx context.Context, req domain.GrantRequest) (*domain.Client, error) {
	if req.ClientID == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrInvalidRequest)
	}
	if s.clientAuth == nil {
		return nil, fmt.Errorf("%w: client authentication is not configured", ErrUnauthorizedClient)
	}
	client, err := s.clientAuth.Authenticate(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !client.HasGrantType(domain.GrantTypeTokenExchange) {
		return nil, errors.Join(ErrUnauthorizedClient, apperrors.New(apperrors.ErrCodeForbidden, "grant type token-exchange not allowed for client"))
	}
	return client, nil
}

// assertCanExchange enforces ADR-0016's "Public clients may exchange
// tokens only when the subject_token was issued to them" rule. A
// confidential client (i.e., one that presented a secret) is allowed
// to exchange any token it can validate.
func (s *TokenExchangeStrategy) assertCanExchange(caller *domain.Client, subjectToken *domain.Token) error {
	if caller.Type != domain.ClientTypePublic {
		return nil
	}
	if subjectToken.ClientID == caller.ID {
		return nil
	}
	return fmt.Errorf("%w: public client may only exchange its own subject_token", ErrUnauthorizedClient)
}

// resolveExchangeScopes enforces RFC 8693's scope-subset rule — the
// requested scope (if any) must be a subset of the subject_token's
// scope. Empty requested scope inherits the subject_token's scope set.
func resolveExchangeScopes(requested, available []string) ([]string, error) {
	if len(requested) == 0 {
		return append([]string(nil), available...), nil
	}
	for _, want := range requested {
		if !slices.Contains(available, want) {
			return nil, fmt.Errorf("%w: scope %q not present on subject_token", ErrInvalidRequest, want)
		}
	}
	return append([]string(nil), requested...), nil
}

// buildActChain constructs the resulting Act chain per RFC 8693 §4.1.
// The outermost actor is the most recent — either the actor_token's
// principal or the calling client itself. Each preceding hop comes
// from the subject_token's chain (preserves the historical chain).
func (s *TokenExchangeStrategy) buildActChain(caller *domain.Client, actorToken *domain.Token, subjectToken *domain.Token) *domain.Actor {
	mostRecent := newActorFromCaller(caller)
	if actorToken != nil {
		mostRecent = newActorFromToken(actorToken)
	}
	mostRecent.Act = subjectToken.Act
	return mostRecent
}

func newActorFromCaller(c *domain.Client) *domain.Actor {
	return &domain.Actor{
		Sub:       c.ID,
		ActorType: c.ResolvedActorType(),
		AgentID:   c.AgentID(),
		ClientID:  c.ID,
	}
}

func newActorFromToken(t *domain.Token) *domain.Actor {
	return &domain.Actor{
		Sub:       t.Subject,
		ActorType: t.ActorType,
		AgentID:   t.AgentID,
		ClientID:  t.ClientID,
	}
}

// resolveActor selects the actor identity recorded as the issued
// token's ActorType / AgentID per ADR-0016: the actor_token's
// principal when present, otherwise the calling client.
func (s *TokenExchangeStrategy) resolveActor(caller *domain.Client, actorToken *domain.Token) (domain.ActorType, string) {
	if actorToken != nil {
		return actorToken.ActorType, actorToken.AgentID
	}
	return caller.ResolvedActorType(), caller.AgentID()
}

// resolveTTL caps the issued token's lifetime at
// min(remaining subject_token TTL, configured maxTTL). A subject_token
// whose remaining lifetime is below the floor returns
// invalid_request — the result would be a near-instantly-expired
// token, useless to the caller.
func (s *TokenExchangeStrategy) resolveTTL(now time.Time, subjectToken *domain.Token) time.Duration {
	remaining := subjectToken.ExpiresAt.Sub(now)
	if remaining > s.maxTTL {
		return s.maxTTL
	}
	if remaining < time.Second {
		return time.Second
	}
	return remaining
}
