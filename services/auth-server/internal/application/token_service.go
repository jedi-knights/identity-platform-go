package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
type JWTClaims struct {
	jwt.RegisteredClaims
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
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
		Scopes:   token.Scopes,
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

func (v *JWTTokenValidator) Validate(_ context.Context, raw string) (*domain.Token, error) {
	token, err := jwt.ParseWithClaims(raw, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.signingKey, nil
	})
	if err != nil {
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
		Scopes:    claims.Scopes,
		ExpiresAt: claims.ExpiresAt.Time,
		IssuedAt:  claims.IssuedAt.Time,
		TokenType: domain.TokenTypeBearer,
		Raw:       raw,
	}, nil
}

// OpaqueTokenGenerator generates opaque tokens.
type OpaqueTokenGenerator struct{}

func NewOpaqueTokenGenerator() *OpaqueTokenGenerator {
	return &OpaqueTokenGenerator{}
}

func (g *OpaqueTokenGenerator) Generate(_ context.Context, _ *domain.Token) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// TokenService handles token introspection and revocation.
type TokenService struct {
	tokenRepo domain.TokenRepository
	validator TokenValidator
}

func NewTokenService(tokenRepo domain.TokenRepository, validator TokenValidator) *TokenService {
	return &TokenService{tokenRepo: tokenRepo, validator: validator}
}

func (s *TokenService) Introspect(ctx context.Context, raw string) (*IntrospectResponse, error) {
	token, err := s.validator.Validate(ctx, raw)
	if err != nil {
		return &IntrospectResponse{Active: false}, nil
	}

	if token.IsExpired() {
		return &IntrospectResponse{Active: false}, nil
	}

	scopeStr := ""
	for i, sc := range token.Scopes {
		if i > 0 {
			scopeStr += " "
		}
		scopeStr += sc
	}

	return &IntrospectResponse{
		Active:    true,
		ClientID:  token.ClientID,
		Subject:   token.Subject,
		Scope:     scopeStr,
		ExpiresAt: token.ExpiresAt.Unix(),
		IssuedAt:  token.IssuedAt.Unix(),
		TokenType: string(token.TokenType),
	}, nil
}

func (s *TokenService) Revoke(_ context.Context, raw string) error {
	return s.tokenRepo.Delete(raw)
}

// IntrospectResponse is the response for token introspection (RFC 7662).
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// generateID generates a random token ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TokenTTL is the default token time-to-live.
const TokenTTL = time.Hour

// ensure generateID is used to avoid lint errors when callers add IDs themselves.
var _ = generateID
