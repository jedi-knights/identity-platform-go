package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// newTestKeySet returns a single-key KeySet for tests. The fresh keypair makes
// each test independent — no shared signing state.
func newTestKeySet(t *testing.T, kid string) *domain.KeySet {
	t.Helper()
	current, err := domain.GenerateSigningKey(kid)
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	ks, err := domain.NewKeySet(current, nil, nil)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return ks
}

func TestRS256TokenGenerator_Generate_RoundTrip(t *testing.T) {
	// Arrange
	ks := newTestKeySet(t, "kid-test-1")
	gen := application.NewRS256TokenGenerator(ks, "test-issuer", nil)
	now := time.Now().Truncate(time.Second)
	tok := &domain.Token{
		ID:        "tok-1",
		ClientID:  "client-a",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		TokenType: domain.TokenTypeBearer,
	}

	// Act
	raw, err := gen.Generate(context.Background(), tok)

	// Assert
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if raw == "" {
		t.Fatal("Generate returned empty token")
	}
}

func TestRS256TokenGenerator_Generate_CarriesKIDHeader(t *testing.T) {
	// Arrange
	ks := newTestKeySet(t, "kid-header-test")
	gen := application.NewRS256TokenGenerator(ks, "test-issuer", nil)
	now := time.Now().Truncate(time.Second)
	tok := &domain.Token{
		ID:        "tok-1",
		ClientID:  "client-a",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		TokenType: domain.TokenTypeBearer,
	}

	// Act
	raw, err := gen.Generate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	parsed, _, err := new(jwt.Parser).ParseUnverified(raw, jwt.MapClaims{})

	// Assert
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	if kid != "kid-header-test" {
		t.Errorf("kid header = %q, want %q", kid, "kid-header-test")
	}
	alg, _ := parsed.Header["alg"].(string)
	if alg != "RS256" {
		t.Errorf("alg header = %q, want %q", alg, "RS256")
	}
}

func TestRS256TokenGenerator_Generate_NilKeySet(t *testing.T) {
	// Arrange — constructor with nil keyset should fail at the boundary.
	// The "Act" step is the constructor call; "Assert" the panic-vs-error contract.
	defer func() {
		// Act / Assert
		if r := recover(); r == nil {
			t.Error("expected NewRS256TokenGenerator(nil, ...) to panic, got nil")
		}
	}()

	// Act
	_ = application.NewRS256TokenGenerator(nil, "test-issuer", nil)
}

func TestRS256TokenValidator_Validate_RoundTrip(t *testing.T) {
	// Arrange
	ks := newTestKeySet(t, "kid-validate-1")
	gen := application.NewRS256TokenGenerator(ks, "test-issuer", nil)
	tokenRepo := newMockTokenRepo()
	validator := application.NewRS256TokenValidator(ks, tokenRepo, "")
	now := time.Now().Truncate(time.Second)
	tok := &domain.Token{
		ID:        "tok-validate",
		ClientID:  "client-a",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		TokenType: domain.TokenTypeBearer,
	}
	raw, err := gen.Generate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Act
	got, err := validator.Validate(context.Background(), raw)

	// Assert
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", got.Subject, "user-1")
	}
	if got.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "client-a")
	}
}

func TestRS256TokenValidator_Validate_RejectsUnknownKID(t *testing.T) {
	// Arrange — sign with one keyset, validate against a different one.
	signingKS := newTestKeySet(t, "kid-signer")
	validatingKS := newTestKeySet(t, "kid-different")
	gen := application.NewRS256TokenGenerator(signingKS, "test-issuer", nil)
	tokenRepo := newMockTokenRepo()
	validator := application.NewRS256TokenValidator(validatingKS, tokenRepo, "")
	now := time.Now().Truncate(time.Second)
	tok := &domain.Token{
		ID:        "tok-unknown-kid",
		ClientID:  "client-a",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		TokenType: domain.TokenTypeBearer,
	}
	raw, err := gen.Generate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Act
	_, err = validator.Validate(context.Background(), raw)

	// Assert
	if err == nil {
		t.Fatal("expected validation to fail for unknown kid, got nil")
	}
}

func TestRS256TokenValidator_Validate_RejectsHS256Token(t *testing.T) {
	// Arrange — sign a token with HS256 manually; the RS256 validator must
	// refuse it as the algorithm-confusion defence (RFC 8725 §3.1).
	ks := newTestKeySet(t, "kid-rs256-only")
	validator := application.NewRS256TokenValidator(ks, newMockTokenRepo(), "")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       "user-1",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iss":       "test-issuer",
		"client_id": "client-a",
	})
	token.Header["typ"] = "at+jwt"
	token.Header["kid"] = "kid-rs256-only"
	raw, err := token.SignedString([]byte("any-hmac-secret-32-bytes-long-ok!"))
	if err != nil {
		t.Fatalf("constructing HS256 token: %v", err)
	}

	// Act
	_, err = validator.Validate(context.Background(), raw)

	// Assert
	if err == nil {
		t.Fatal("expected RS256 validator to reject HS256-signed token, got nil")
	}
}

func TestRS256TokenValidator_Validate_RejectsExpiredToken(t *testing.T) {
	// Arrange
	ks := newTestKeySet(t, "kid-expiry-test")
	gen := application.NewRS256TokenGenerator(ks, "test-issuer", nil)
	validator := application.NewRS256TokenValidator(ks, newMockTokenRepo(), "")
	past := time.Now().Add(-2 * time.Hour)
	tok := &domain.Token{
		ID:        "tok-expired",
		ClientID:  "client-a",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  past,
		ExpiresAt: past.Add(time.Hour),
		TokenType: domain.TokenTypeBearer,
	}
	raw, err := gen.Generate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Act
	_, err = validator.Validate(context.Background(), raw)

	// Assert
	if err == nil {
		t.Fatal("expected validation to fail for expired token, got nil")
	}
}

func TestRS256TokenValidator_Validate_VerifiesIssuerWhenSet(t *testing.T) {
	// Arrange — validator configured with one issuer; sign a token from a different one.
	ks := newTestKeySet(t, "kid-iss-test")
	gen := application.NewRS256TokenGenerator(ks, "wrong-issuer", nil)
	validator := application.NewRS256TokenValidator(ks, newMockTokenRepo(), "expected-issuer")
	now := time.Now().Truncate(time.Second)
	tok := &domain.Token{
		ID:        "tok-iss",
		ClientID:  "client-a",
		Subject:   "user-1",
		Scopes:    []string{"read"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		TokenType: domain.TokenTypeBearer,
	}
	raw, err := gen.Generate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Act
	_, err = validator.Validate(context.Background(), raw)

	// Assert
	if err == nil {
		t.Fatal("expected validation to fail for wrong issuer, got nil")
	}
}
