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

func TestLoad_OIDCIssuerReadFromEnv(t *testing.T) {
	// Arrange — every other jwt.* field has a v.SetDefault call in Load;
	// oidc_issuer previously had none, which meant viper's AutomaticEnv
	// never surfaced AUTH_JWT_OIDC_ISSUER through Unmarshal — id_token
	// issuance was unreachable via env var configuration in practice.
	t.Setenv("AUTH_JWT_SIGNING_KEY", "")
	t.Setenv("AUTH_JWT_OIDC_ISSUER", "https://issuer.example.com")

	// Act
	cfg, err := config.Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWT.OIDCIssuer != "https://issuer.example.com" {
		t.Errorf("OIDCIssuer = %q, want %q", cfg.JWT.OIDCIssuer, "https://issuer.example.com")
	}
}

func TestLoad_IDTokenTTLSecondsReadFromEnv(t *testing.T) {
	// Arrange — same missing-default gap as OIDCIssuer: with no default,
	// AUTH_JWT_ID_TOKEN_TTL_SECONDS never reached the struct, silently
	// leaving IDTokenTTLSeconds at its zero value (id_token issued with
	// exp == iat, i.e. already expired).
	t.Setenv("AUTH_JWT_SIGNING_KEY", "")
	t.Setenv("AUTH_JWT_ID_TOKEN_TTL_SECONDS", "600")

	// Act
	cfg, err := config.Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWT.IDTokenTTLSeconds != 600 {
		t.Errorf("IDTokenTTLSeconds = %d, want 600", cfg.JWT.IDTokenTTLSeconds)
	}
}

func TestLoad_IDTokenTTLSecondsDefaultsTo300(t *testing.T) {
	// Arrange — no AUTH_JWT_ID_TOKEN_TTL_SECONDS set.
	t.Setenv("AUTH_JWT_SIGNING_KEY", "")

	// Act
	cfg, err := config.Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWT.IDTokenTTLSeconds != 300 {
		t.Errorf("default IDTokenTTLSeconds = %d, want 300", cfg.JWT.IDTokenTTLSeconds)
	}
}
