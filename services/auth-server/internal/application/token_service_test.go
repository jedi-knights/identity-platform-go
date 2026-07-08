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
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer", nil)

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
	if err := tokenRepo.Save(context.Background(), domainToken); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo, "")
	svc := application.NewTokenService(tokenRepo, nil, validator)

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

// TestTokenService_Introspect_EchoesAcr covers ADR-0024: the acr value
// stamped on the stored domain.Token (never lifted onto the JWT itself)
// must still surface in the introspection response, sourced from the
// token store rather than the JWT-validated claims.
func TestTokenService_Introspect_EchoesAcr(t *testing.T) {
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer", nil)

	domainToken := &domain.Token{
		ID:        "t1",
		ClientID:  "client1",
		Subject:   "user1",
		Scopes:    []string{"read"},
		Acr:       domain.AcrValuePassword,
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		TokenType: domain.TokenTypeBearer,
	}

	raw, err := gen.Generate(context.Background(), domainToken)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	domainToken.Raw = raw
	if err := tokenRepo.Save(context.Background(), domainToken); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo, "")
	svc := application.NewTokenService(tokenRepo, nil, validator)

	resp, err := svc.Introspect(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Acr != domain.AcrValuePassword {
		t.Errorf("Acr = %q, want %q", resp.Acr, domain.AcrValuePassword)
	}
}

// TestTokenService_Introspect_EchoesDPoPConfirmation covers RFC 9449 §6.1
// (ADR-0025): a DPoP-bound token's stored JKT must surface as
// "cnf":{"jkt":...} on introspection. Only the stored domain.Token carries
// JKT — the JWT-validated token has no field for it — so this pins the same
// "use the stored token, not the JWT-validated one" fix Introspect already
// needs for RFC 9396/ADR-0024-style fields.
func TestTokenService_Introspect_EchoesDPoPConfirmation(t *testing.T) {
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer", nil)

	domainToken := &domain.Token{
		ID:        "t-dpop",
		ClientID:  "client1",
		Subject:   "client1",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		TokenType: domain.TokenTypeDPoP,
		JKT:       "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
	}

	raw, err := gen.Generate(context.Background(), domainToken)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	domainToken.Raw = raw
	if err := tokenRepo.Save(context.Background(), domainToken); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo, "")
	svc := application.NewTokenService(tokenRepo, nil, validator)

	resp, err := svc.Introspect(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CNF == nil {
		t.Fatal("expected a non-nil cnf claim for a DPoP-bound token")
	}
	if resp.CNF.JKT != domainToken.JKT {
		t.Errorf("cnf.jkt = %q, want %q", resp.CNF.JKT, domainToken.JKT)
	}
	if resp.TokenType != string(domain.TokenTypeDPoP) {
		t.Errorf("token_type = %q, want %q", resp.TokenType, domain.TokenTypeDPoP)
	}
}

func TestTokenService_Introspect_ExpiredToken(t *testing.T) {
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer", nil)

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

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo, "")
	svc := application.NewTokenService(tokenRepo, nil, validator)

	resp, err := svc.Introspect(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false for expired token")
	}
}

func TestTokenService_Introspect_RevokedToken(t *testing.T) {
	// A token that passes JWT validation but has been removed from the store
	// (i.e., was revoked) must be reported as inactive.
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer", nil)

	domainToken := &domain.Token{
		ID:        "t4",
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
	// Do NOT save to tokenRepo — simulates a previously revoked token.

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo, "")
	svc := application.NewTokenService(tokenRepo, nil, validator)

	resp, err := svc.Introspect(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false for revoked (not-in-store) token")
	}
}

func TestTokenService_Revoke(t *testing.T) {
	tokenRepo := newMockTokenRepo()
	gen := application.NewJWTTokenGenerator(testSigningKey, "test-issuer", nil)

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
	if err := tokenRepo.Save(context.Background(), domainToken); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	validator := application.NewJWTTokenValidator(testSigningKey, tokenRepo, "")
	svc := application.NewTokenService(tokenRepo, nil, validator)

	if err := svc.Revoke(context.Background(), raw); err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}

	if _, err := tokenRepo.FindByRaw(context.Background(), raw); err == nil {
		t.Error("expected token to be deleted after revoke")
	}
}
