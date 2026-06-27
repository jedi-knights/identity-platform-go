package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
)

func newRouterMetadataHandler(t *testing.T, oidc bool) *authhttp.MetadataHandler {
	t.Helper()
	cfg := application.MetadataBuilderConfig{
		PublicBaseURL: "https://auth.example.com",
		Issuer:        "auth-server",
		SigningAlg:    "RS256",
		HasJWKS:       true,
		HasLoginUI:    true,
	}
	if oidc {
		cfg.OIDCIssuer = "https://oidc.example.com"
		cfg.HasUserInfo = true
	}
	return authhttp.NewMetadataHandler(application.NewMetadataBuilder(cfg))
}

func TestNewRouter_MetadataRoutes_RegisteredWhenHandlerNonNil(t *testing.T) {
	router := authhttp.NewRouter(&authhttp.Handler{}, nil, nil, newRouterMetadataHandler(t, true), quietLogger())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
	}
}

func TestNewRouter_MetadataRoutes_404WhenHandlerNil(t *testing.T) {
	router := authhttp.NewRouter(&authhttp.Handler{}, nil, nil, nil, quietLogger())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 when metadata disabled", path, resp.StatusCode)
		}
	}
}
