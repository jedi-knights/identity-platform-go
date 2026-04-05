package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// TokenGenerator defines how tokens are generated (Strategy pattern).
type TokenGenerator interface {
	Generate(ctx context.Context, token *domain.Token) (string, error)
}

// TokenValidator validates tokens and returns token info.
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (*domain.Token, error)
}

// JWTTokenGenerator generates JWT tokens (Strategy).
type JWTTokenGenerator struct {
	signingKey []byte
	issuer     string
}

func NewJWTTokenGenerator(signingKey []byte, issuer string) *JWTTokenGenerator {
	return &JWTTokenGenerator{signingKey: signingKey, issuer: issuer}
}

func (g *JWTTokenGenerator) Generate(_ context.Context, token *domain.Token) (string, error) {
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:      g.issuer,
		Subject:     token.Subject,
		TokenID:     token.ID,
		ClientID:    token.ClientID,
		Scope:       strings.Join(token.Scopes, " "),
		Roles:       token.Roles,
		Permissions: token.Permissions,
		IssuedAt:    token.IssuedAt,
		ExpiresAt:   token.ExpiresAt,
	})
	return jwtutil.Sign(claims, g.signingKey)
}

// JWTTokenValidator validates JWT tokens (Strategy).
type JWTTokenValidator struct {
	signingKey []byte
	tokenRepo  domain.TokenRepository
}

func NewJWTTokenValidator(signingKey []byte, tokenRepo domain.TokenRepository) *JWTTokenValidator {
	return &JWTTokenValidator{signingKey: signingKey, tokenRepo: tokenRepo}
}

func (v *JWTTokenValidator) Validate(_ context.Context, raw string) (*domain.Token, error) {
	claims, err := jwtutil.Parse(raw, v.signingKey)
	if err != nil {
		// All errors from jwtutil.Parse with a local key are token-validation failures
		// (expired, bad signature, malformed), not infrastructure errors.
		// Callers should treat this as {active:false}.
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return &domain.Token{
		ID:        claims.ID,
		ClientID:  claims.ClientID,
		Subject:   claims.Subject,
		Scopes:    strings.Fields(claims.Scope),
		ExpiresAt: claims.ExpiresAt.Time,
		IssuedAt:  claims.IssuedAt.Time,
		TokenType: domain.TokenTypeBearer,
		Raw:       raw,
	}, nil
}

// TokenService handles token introspection and revocation.
type TokenService struct {
	tokenRepo        domain.TokenRepository
	refreshTokenRepo domain.RefreshTokenRepository
	validator        TokenValidator
}

// NewTokenService creates a TokenService.
// refreshTokenRepo may be nil — when nil, revocation only attempts access token deletion.
func NewTokenService(tokenRepo domain.TokenRepository, refreshTokenRepo domain.RefreshTokenRepository, validator TokenValidator) *TokenService {
	return &TokenService{tokenRepo: tokenRepo, refreshTokenRepo: refreshTokenRepo, validator: validator}
}

func (s *TokenService) Introspect(ctx context.Context, raw string) (*domain.IntrospectResponse, error) {
	token, err := s.validator.Validate(ctx, raw)
	if err != nil {
		// Token validation failures (expired, bad sig, malformed) → inactive.
		// All errors from JWTTokenValidator are token-invalid, not infra failures.
		return &domain.IntrospectResponse{Active: false}, nil
	}

	if token.IsExpiredAt(time.Now()) {
		return &domain.IntrospectResponse{Active: false}, nil
	}

	// Check the token store — if not present, the token was revoked.
	if _, err := s.tokenRepo.FindByRaw(ctx, raw); err != nil {
		if errors.Is(err, domain.ErrTokenNotFound) {
			return &domain.IntrospectResponse{Active: false}, nil
		}
		return nil, fmt.Errorf("checking token store: %w", err)
	}

	scopeStr := strings.Join(token.Scopes, " ")

	return &domain.IntrospectResponse{
		Active:    true,
		ClientID:  token.ClientID,
		Subject:   token.Subject,
		Scope:     scopeStr,
		ExpiresAt: token.ExpiresAt.Unix(),
		IssuedAt:  token.IssuedAt.Unix(),
		TokenType: string(token.TokenType),
	}, nil
}

// Revoke revokes the presented token, attempting deletion from both the access token
// and refresh token stores (RFC 7009 §2 — revoke related tokens).
// Not-found errors are treated as idempotent success per RFC 7009 §2.2.
func (s *TokenService) Revoke(ctx context.Context, raw string) error {
	// Attempt to revoke as access token; idempotent — not found is not an error.
	// The Redis adapter returns apperrors.ErrCodeNotFound for missing tokens;
	// the in-memory adapter returns domain.ErrTokenNotFound. Accept both.
	if err := s.tokenRepo.Delete(ctx, raw); err != nil &&
		!errors.Is(err, domain.ErrTokenNotFound) &&
		!apperrors.IsNotFound(err) {
		return fmt.Errorf("revoking access token: %w", err)
	}
	// Attempt to revoke as refresh token; idempotent.
	if s.refreshTokenRepo != nil {
		if err := s.refreshTokenRepo.Delete(ctx, raw); err != nil && !errors.Is(err, domain.ErrRefreshTokenNotFound) {
			return fmt.Errorf("revoking refresh token: %w", err)
		}
	}
	return nil
}

// generateID generates a random token ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
