package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

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

// JWTClaims are the JWT claims for an access token.
// Scope is a space-delimited string per RFC 9068 §2.2.3.1.
type JWTClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
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
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuer,
			Subject:   token.Subject,
			ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(token.IssuedAt),
			ID:        token.ID,
		},
		ClientID: token.ClientID,
		Scope:    strings.Join(token.Scopes, " "),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(g.signingKey)
}

// JWTTokenValidator validates JWT tokens (Strategy).
type JWTTokenValidator struct {
	signingKey []byte
	tokenRepo  domain.TokenRepository
}

func NewJWTTokenValidator(signingKey []byte, tokenRepo domain.TokenRepository) *JWTTokenValidator {
	return &JWTTokenValidator{signingKey: signingKey, tokenRepo: tokenRepo}
}

func (v *JWTTokenValidator) Validate(ctx context.Context, raw string) (*domain.Token, error) {
	token, err := jwt.ParseWithClaims(raw, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.signingKey, nil
	})
	if err != nil {
		// All errors from jwt.ParseWithClaims with a static local keyFunc are
		// token-validation failures (expired, bad signature, malformed), not
		// infrastructure errors. Callers should treat this as {active:false}.
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
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
	tokenRepo domain.TokenRepository
	validator TokenValidator
}

func NewTokenService(tokenRepo domain.TokenRepository, validator TokenValidator) *TokenService {
	return &TokenService{tokenRepo: tokenRepo, validator: validator}
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

func (s *TokenService) Revoke(ctx context.Context, raw string) error {
	return s.tokenRepo.Delete(ctx, raw)
}

// generateID generates a random token ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
