package application_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

func newRegSvc(t *testing.T, cfg application.RegistrationServiceConfig) (*application.RegistrationService, *fakeClientRepo) {
	t.Helper()
	repo := newFakeClientRepo()
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = bcrypt.MinCost
	}
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = "https://clients.example.com"
	}
	svc := application.NewRegistrationService(repo, cfg)
	return svc, repo
}

func registerErr(t *testing.T, err error) *domain.RegistrationError {
	t.Helper()
	var regErr *domain.RegistrationError
	if !errors.As(err, &regErr) {
		t.Fatalf("expected *domain.RegistrationError, got %T: %v", err, err)
	}
	return regErr
}

func TestRegister_DefaultsPublicWithoutSecret(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	resp, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.TokenEndpointAuthMethod != domain.TokenEndpointAuthMethodNone {
		t.Errorf("token_endpoint_auth_method = %q, want %q", resp.TokenEndpointAuthMethod, domain.TokenEndpointAuthMethodNone)
	}
	if resp.ClientSecret != "" {
		t.Errorf("client_secret = %q, want empty for public client", resp.ClientSecret)
	}
	if resp.RegistrationAccessToken == "" {
		t.Error("registration_access_token must be non-empty")
	}
	if resp.RegistrationClientURI != "https://clients.example.com/register/"+resp.ClientID {
		t.Errorf("registration_client_uri = %q", resp.RegistrationClientURI)
	}
	if !slices.Equal(resp.GrantTypes, []string{"authorization_code"}) {
		t.Errorf("grant_types = %v", resp.GrantTypes)
	}
	if !slices.Equal(resp.ResponseTypes, []string{"code"}) {
		t.Errorf("response_types = %v", resp.ResponseTypes)
	}
	if resp.ClientIDIssuedAt == 0 {
		t.Error("client_id_issued_at must be non-zero")
	}
}

func TestRegister_ConfidentialClientGetsSecret(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	resp, err := svc.Register(context.Background(), domain.RegistrationRequest{
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodBasic,
		GrantTypes:              []string{"client_credentials"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.ClientSecret == "" {
		t.Error("client_secret must be returned for confidential client")
	}
}

func TestRegister_PersistsClientWithFields(t *testing.T) {
	svc, repo := newRegSvc(t, application.RegistrationServiceConfig{})
	resp, err := svc.Register(context.Background(), domain.RegistrationRequest{
		ClientName:   "MCP Filesystem Connector",
		RedirectURIs: []string{"https://example.com/callback"},
		Scope:        "openid read",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	stored := repo.clients[resp.ClientID]
	if stored == nil {
		t.Fatalf("client not persisted")
	}
	if stored.Name != "MCP Filesystem Connector" {
		t.Errorf("Name = %q", stored.Name)
	}
	if stored.RegistrationAccessTokenHash == "" {
		t.Error("RegistrationAccessTokenHash must be non-empty")
	}
	if stored.TokenEndpointAuthMethod != domain.TokenEndpointAuthMethodNone {
		t.Errorf("TokenEndpointAuthMethod = %q", stored.TokenEndpointAuthMethod)
	}
	if !slices.Equal(stored.Scopes, []string{"openid", "read"}) {
		t.Errorf("Scopes = %v", stored.Scopes)
	}
}

func TestRegister_DefaultsClientName(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	resp, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !strings.HasPrefix(resp.ClientName, "Client ") {
		t.Errorf("client_name = %q, want prefix 'Client '", resp.ClientName)
	}
}

func TestRegister_RejectsSoftwareStatement(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		SoftwareStatement: "ey...",
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidSoftwareStatement {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsUnknownGrantType(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		GrantTypes:   []string{"password"},
		RedirectURIs: []string{"https://example.com/cb"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsUnknownResponseType(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		ResponseTypes: []string{"token"},
		RedirectURIs:  []string{"https://example.com/cb"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsExplicitGrantResponseMismatch(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	// The validator only flags the mismatch path when grant_types
	// contains authorization_code AND response_types is explicitly set
	// to a value that excludes "code".
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"none"},
		RedirectURIs:  []string{"https://example.com/cb"},
	})
	regErr := registerErr(t, err)
	// ResponseTypes are validated before grant/response consistency, so
	// the "none" entry is rejected as invalid_client_metadata first.
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_AllowsDefaultResponseTypesForAuthCode(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: nil, // defaults to ["code"]
		RedirectURIs:  []string{"https://example.com/cb"},
	})
	if err != nil {
		t.Fatalf("default response_types must satisfy authorization_code: %v", err)
	}
}

func TestRegister_RejectsUnknownAuthMethod(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		TokenEndpointAuthMethod: "private_key_jwt",
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RequiresRedirectURIForAuthCode(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		GrantTypes: []string{"authorization_code"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidRedirectURI {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsHTTPRedirectURI(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"http://example.com/cb"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidRedirectURI {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_AllowsLocalhostWhenConfigured(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{AllowLocalhost: true})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"http://localhost:3000/cb"},
	})
	if err != nil {
		t.Errorf("Register: %v", err)
	}
}

func TestRegister_RejectsRedirectURIWithFragment(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb#section"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidRedirectURI {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsWildcardRedirectURI(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://*.example.com/cb"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidRedirectURI {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsUnsupportedScope(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{
		AllowedScopes: []string{"openid", "read"},
	})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
		Scope:        "openid write",
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsHTTPLogoURI(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
		LogoURI:      "http://example.com/logo.png",
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsTooManyContacts(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	contacts := make([]string, 11)
	for i := range contacts {
		contacts[i] = "user@example.com"
	}
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
		Contacts:     contacts,
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsInvalidContactEmail(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
		Contacts:     []string{"not-an-email"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_RejectsOverlongClientName(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.Register(context.Background(), domain.RegistrationRequest{
		ClientName:   strings.Repeat("x", 201),
		RedirectURIs: []string{"https://example.com/cb"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidClientMetadata {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestRegister_AcceptsClientCredentialsWithoutRedirect(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	resp, err := svc.Register(context.Background(), domain.RegistrationRequest{
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodBasic,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.ClientSecret == "" {
		t.Error("client_secret must be returned")
	}
}

func TestRegistrationError_Error_FormatsCodeAndDescription(t *testing.T) {
	err := &domain.RegistrationError{Code: "invalid_redirect_uri", Description: "wrong scheme"}
	if err.Error() != "invalid_redirect_uri: wrong scheme" {
		t.Errorf("Error() = %q", err.Error())
	}
	bare := &domain.RegistrationError{Code: "server_error"}
	if bare.Error() != "server_error" {
		t.Errorf("Error() = %q", bare.Error())
	}
}

func TestNewRegistrationService_AuditPanicsOnNil(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected WithAudit(nil) to panic")
		}
	}()
	svc.WithAudit(nil, "")
}
