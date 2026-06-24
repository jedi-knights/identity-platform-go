package config_test

import (
	"strings"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/config"
)

func TestLoad_DefaultSigningAlgIsRS256(t *testing.T) {
	// Arrange — no AUTH_* env vars set; no insecure HS256 key.
	t.Setenv("AUTH_JWT_SIGNING_KEY", "")

	// Act
	cfg, err := config.Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWT.SigningAlg != "RS256" {
		t.Errorf("default SigningAlg = %q, want %q", cfg.JWT.SigningAlg, "RS256")
	}
}

func TestLoad_RS256AcceptsEmptyHS256Key(t *testing.T) {
	// Arrange — RS256 mode does not need the HS256 signing_key.
	t.Setenv("AUTH_JWT_SIGNING_ALG", "RS256")
	t.Setenv("AUTH_JWT_SIGNING_KEY", "")

	// Act
	cfg, err := config.Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWT.SigningAlg != "RS256" {
		t.Errorf("SigningAlg = %q, want %q", cfg.JWT.SigningAlg, "RS256")
	}
}

func TestLoad_HS256StillRequiresStrongKey(t *testing.T) {
	// Arrange — explicit HS256 mode without a strong key must fail validation.
	t.Setenv("AUTH_JWT_SIGNING_ALG", "HS256")
	t.Setenv("AUTH_JWT_SIGNING_KEY", "too-short")

	// Act
	_, err := config.Load()

	// Assert
	if err == nil {
		t.Fatal("expected error for HS256 with short signing key, got nil")
	}
	if !strings.Contains(err.Error(), "signing") {
		t.Errorf("error = %v, want one mentioning 'signing'", err)
	}
}

func TestLoad_HS256RejectsInsecureDefault(t *testing.T) {
	// Arrange
	t.Setenv("AUTH_JWT_SIGNING_ALG", "HS256")
	t.Setenv("AUTH_JWT_SIGNING_KEY", "change-me-in-production")

	// Act
	_, err := config.Load()

	// Assert
	if err == nil {
		t.Fatal("expected error for insecure default HS256 key, got nil")
	}
}

func TestLoad_UnknownSigningAlgRejected(t *testing.T) {
	// Arrange
	t.Setenv("AUTH_JWT_SIGNING_ALG", "ES256") // not yet supported
	t.Setenv("AUTH_JWT_SIGNING_KEY", "")

	// Act
	_, err := config.Load()

	// Assert
	if err == nil {
		t.Fatal("expected error for unsupported signing alg, got nil")
	}
}

func TestLoad_RS256WithMalformedPEMRejected(t *testing.T) {
	// Arrange
	t.Setenv("AUTH_JWT_SIGNING_ALG", "RS256")
	t.Setenv("AUTH_JWT_SIGNING_KEY", "")
	t.Setenv("AUTH_JWT_RSA_PRIVATE_KEY_PEM", "definitely not pem")

	// Act
	_, err := config.Load()

	// Assert
	if err == nil {
		t.Fatal("expected error for malformed RSA PEM, got nil")
	}
}
