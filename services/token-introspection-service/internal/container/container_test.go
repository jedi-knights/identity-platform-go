package container_test

import (
	"context"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	platform "github.com/jedi-knights/go-platform/container"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/config"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/container"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

func newQuietLogger() logging.Logger {
	return logging.New(logging.Config{Level: "error", Format: "text", Environment: "test"})
}

func TestNew_HS256Mode_WiresUp(t *testing.T) {
	// Arrange — INTROSPECT_JWT_JWKS_URL unset; legacy HS256 path.
	cfg := &config.Config{
		JWT: config.JWTConfig{
			SigningKey: "a-valid-32-char-signing-key-here!!",
			Issuer:     "",
		},
		Introspection: config.IntrospectionConfig{Secret: "intro-secret"},
	}

	// Act
	c, err := container.New(context.Background(), cfg, newQuietLogger())

	// Assert
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v := platform.MustResolve[domain.TokenValidator](context.Background(), c); v == nil {
		t.Fatal("TokenValidator is nil")
	}
}

func TestNew_JWKSMode_WiresUp(t *testing.T) {
	// Arrange — JWKS URL configured; no HS256 SigningKey required.
	cfg := &config.Config{
		JWT: config.JWTConfig{
			JWKSURL:      "https://auth.example.com/.well-known/jwks.json",
			JWKSCacheTTL: "1h",
		},
		Introspection: config.IntrospectionConfig{Secret: "intro-secret"},
	}

	// Act
	c, err := container.New(context.Background(), cfg, newQuietLogger())

	// Assert
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v := platform.MustResolve[domain.TokenValidator](context.Background(), c); v == nil {
		t.Fatal("TokenValidator is nil")
	}
}
