package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
)

// quietLogger returns a no-op logger so router tests do not pollute stdout.
func quietLogger() logging.Logger {
	return logging.New(logging.Config{Level: "error", Format: "text", Environment: "test"})
}

func TestNewRouter_JWKSRoute_RegisteredWhenHandlerNonNil(t *testing.T) {
	// Arrange — minimal Handler is fine; the JWKS route is registered
	// independently and we only probe that route.
	ks := newSingleKeySet(t, "kid-router")
	jwks := authhttp.NewJWKSHandler(ks)
	router := authhttp.NewRouter(&authhttp.Handler{}, jwks, quietLogger())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Act
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")

	// Assert
	if err != nil {
		t.Fatalf("GET /.well-known/jwks.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewRouter_JWKSRoute_404WhenHandlerNil(t *testing.T) {
	// Arrange — HS256 mode: jwks handler resolved as nil, route not registered.
	router := authhttp.NewRouter(&authhttp.Handler{}, nil, quietLogger())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Act
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")

	// Assert
	if err != nil {
		t.Fatalf("GET /.well-known/jwks.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
