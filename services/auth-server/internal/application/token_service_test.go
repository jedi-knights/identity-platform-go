package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

var testSigningKey = []byte("test-signing-key-32-bytes-long!!")

func TestTokenService_Introspect_ValidToken(t *testing.T) {
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer")

	domainToken := &domain.Token{
		ID:        "t1",
		ClientID:  "client1",
		Subject:   "user1",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		TokenType: domain.TokenTypeBearer,
	}

	raw, err := gen.Generate(context.Background(), domainToken)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	domainToken.Raw = raw
	_ = tokenRepo.Save(domainToken)

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo)
	svc := application.NewTokenService(tokenRepo, validator)

	resp, err := svc.Introspect(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Active {
		t.Error("expected active=true for valid token")
	}
	if resp.Subject != "user1" {
		t.Errorf("expected subject user1, got %s", resp.Subject)
	}
}

func TestTokenService_Introspect_ExpiredToken(t *testing.T) {
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer")

	domainToken := &domain.Token{
		ID:        "t2",
		ClientID:  "client1",
		Subject:   "user1",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(-time.Hour), // expired
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		TokenType: domain.TokenTypeBearer,
	}

	raw, err := gen.Generate(context.Background(), domainToken)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	domainToken.Raw = raw

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo)
	svc := application.NewTokenService(tokenRepo, validator)

	resp, err := svc.Introspect(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false for expired token")
	}
}

func TestTokenService_Revoke(t *testing.T) {
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer")

	domainToken := &domain.Token{
		ID:        "t3",
		ClientID:  "client1",
		Subject:   "user1",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		TokenType: domain.TokenTypeBearer,
	}

	raw, err := gen.Generate(context.Background(), domainToken)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	domainToken.Raw = raw
	_ = tokenRepo.Save(domainToken)

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo)
	svc := application.NewTokenService(tokenRepo, validator)

	if err := svc.Revoke(context.Background(), raw); err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}

	if _, err := tokenRepo.FindByRaw(raw); err == nil {
		t.Error("expected token to be deleted after revoke")
	}
}
