package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func newOAuthMetadataHandler(t *testing.T) *authhttp.MetadataHandler {
	t.Helper()
	builder := application.NewMetadataBuilder(application.MetadataBuilderConfig{
		PublicBaseURL: "https://auth.example.com",
		Issuer:        "auth-server",
		SigningAlg:    "RS256",
		HasJWKS:       true,
		HasLoginUI:    true,
	})
	return authhttp.NewMetadataHandler(builder)
}

func newOIDCMetadataHandler(t *testing.T) *authhttp.MetadataHandler {
	t.Helper()
	builder := application.NewMetadataBuilder(application.MetadataBuilderConfig{
		PublicBaseURL: "https://auth.example.com",
		Issuer:        "auth-server",
		OIDCIssuer:    "https://oidc.example.com",
		SigningAlg:    "RS256",
		HasJWKS:       true,
		HasUserInfo:   true,
		HasLoginUI:    true,
	})
	return authhttp.NewMetadataHandler(builder)
}

func TestMetadataHandler_OAuthMetadata_ReturnsOK(t *testing.T) {
	h := newOAuthMetadataHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)

	h.OAuthMetadata(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q, want a JSON variant", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
	}

	var body domain.AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Issuer != "auth-server" {
		t.Errorf("issuer = %q, want %q", body.Issuer, "auth-server")
	}
	if body.TokenEndpoint != "https://auth.example.com/oauth/token" {
		t.Errorf("token_endpoint = %q", body.TokenEndpoint)
	}
}

func TestMetadataHandler_OAuthMetadata_OmitsOIDCFields(t *testing.T) {
	h := newOAuthMetadataHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)

	h.OAuthMetadata(w, r)

	body := w.Body.String()
	if strings.Contains(body, "subject_types_supported") {
		t.Errorf("RFC 8414 document leaked OIDC field; body = %s", body)
	}
	if strings.Contains(body, "userinfo_endpoint") {
		t.Errorf("RFC 8414 document leaked userinfo_endpoint; body = %s", body)
	}
}

func TestMetadataHandler_OIDCMetadata_ReturnsOIDCShape(t *testing.T) {
	h := newOIDCMetadataHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)

	h.OIDCMetadata(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body domain.AuthorizationServerMetadata
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Issuer != "https://oidc.example.com" {
		t.Errorf("issuer = %q, want OIDC issuer", body.Issuer)
	}
	if body.UserInfoEndpoint != "https://auth.example.com/userinfo" {
		t.Errorf("userinfo_endpoint = %q", body.UserInfoEndpoint)
	}
	if len(body.SubjectTypesSupported) == 0 {
		t.Errorf("subject_types_supported is empty")
	}
}

func TestMetadataHandler_SetsCacheControl(t *testing.T) {
	h := newOIDCMetadataHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)

	h.OIDCMetadata(w, r)

	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
	}
}

func TestNewMetadataHandler_NilBuilderPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected NewMetadataHandler(nil) to panic, got nil")
		}
	}()
	_ = authhttp.NewMetadataHandler(nil)
}
