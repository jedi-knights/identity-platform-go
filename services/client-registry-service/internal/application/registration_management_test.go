package application_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// registerThenGetToken registers a client and returns the issued
// registration_access_token plus the client_id, so management tests can
// exercise the RFC 7592 endpoints against a real, just-issued token
// rather than a fixture they had to hash by hand.
func registerThenGetToken(t *testing.T, svc *application.RegistrationService) (clientID, token string) {
	t.Helper()
	resp, err := svc.Register(context.Background(), domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return resp.ClientID, resp.RegistrationAccessToken
}

func TestReadRegistration_ReturnsMetadata(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, token := registerThenGetToken(t, svc)

	resp, err := svc.ReadRegistration(context.Background(), clientID, token)
	if err != nil {
		t.Fatalf("ReadRegistration: %v", err)
	}
	if resp.ClientID != clientID {
		t.Errorf("ClientID = %q", resp.ClientID)
	}
	if resp.RegistrationAccessToken != "" {
		t.Error("management read must not re-emit the registration access token")
	}
	if resp.RegistrationClientURI == "" {
		t.Error("registration_client_uri must be present")
	}
}

func TestReadRegistration_NotFoundForUnknownClient(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	_, err := svc.ReadRegistration(context.Background(), "does-not-exist", "tok")
	regErr := registerErr(t, err)
	if regErr.Code != "not_found" {
		t.Errorf("code = %q, want not_found", regErr.Code)
	}
}

func TestReadRegistration_NotFoundOnBadToken(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, _ := registerThenGetToken(t, svc)

	_, err := svc.ReadRegistration(context.Background(), clientID, "wrong-token-value")
	regErr := registerErr(t, err)
	if regErr.Code != "not_found" {
		t.Errorf("code = %q, want not_found (must not leak client existence)", regErr.Code)
	}
}

func TestReadRegistration_InvalidTokenOnMissingHeader(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, _ := registerThenGetToken(t, svc)

	_, err := svc.ReadRegistration(context.Background(), clientID, "")
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidToken {
		t.Errorf("code = %q, want invalid_token", regErr.Code)
	}
}

func TestUpdateRegistration_ReplacesMetadata(t *testing.T) {
	svc, repo := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, token := registerThenGetToken(t, svc)

	resp, err := svc.UpdateRegistration(context.Background(), clientID, token, domain.RegistrationRequest{
		ClientName:   "Updated",
		RedirectURIs: []string{"https://new.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("UpdateRegistration: %v", err)
	}
	if resp.ClientName != "Updated" {
		t.Errorf("client_name = %q", resp.ClientName)
	}
	stored := repo.clients[clientID]
	if stored.Name != "Updated" {
		t.Errorf("Name in store = %q", stored.Name)
	}
	if len(stored.RedirectURIs) != 1 || stored.RedirectURIs[0] != "https://new.example.com/cb" {
		t.Errorf("RedirectURIs = %v", stored.RedirectURIs)
	}
}

func TestUpdateRegistration_IssuesNewSecretOnConfidentialUpgrade(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, token := registerThenGetToken(t, svc)

	resp, err := svc.UpdateRegistration(context.Background(), clientID, token, domain.RegistrationRequest{
		ClientName:              "Upgraded",
		RedirectURIs:            []string{"https://example.com/cb"},
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodBasic,
	})
	if err != nil {
		t.Fatalf("UpdateRegistration: %v", err)
	}
	if resp.ClientSecret == "" {
		t.Error("client_secret must be returned when upgrading from public to confidential")
	}
}

func TestUpdateRegistration_RevalidatesRedirectURIs(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, token := registerThenGetToken(t, svc)

	_, err := svc.UpdateRegistration(context.Background(), clientID, token, domain.RegistrationRequest{
		RedirectURIs: []string{"http://example.com/cb"}, // bad scheme
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidRedirectURI {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestUpdateRegistration_NotFoundOnBadToken(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, _ := registerThenGetToken(t, svc)

	_, err := svc.UpdateRegistration(context.Background(), clientID, "wrong", domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
	})
	regErr := registerErr(t, err)
	if regErr.Code != "not_found" {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestUpdateRegistration_RejectsSoftwareStatement(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, token := registerThenGetToken(t, svc)

	_, err := svc.UpdateRegistration(context.Background(), clientID, token, domain.RegistrationRequest{
		SoftwareStatement: "ey...",
	})
	regErr := registerErr(t, err)
	if regErr.Code != domain.RegistrationErrorInvalidSoftwareStatement {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestUpdateRegistration_PreservesNameWhenAbsent(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, token := registerThenGetToken(t, svc)

	resp, err := svc.UpdateRegistration(context.Background(), clientID, token, domain.RegistrationRequest{
		RedirectURIs: []string{"https://example.com/cb"},
	})
	if err != nil {
		t.Fatalf("UpdateRegistration: %v", err)
	}
	if !strings.HasPrefix(resp.ClientName, "Client ") {
		t.Errorf("client_name dropped on empty update: %q", resp.ClientName)
	}
}

func TestDeleteRegistration_RemovesClient(t *testing.T) {
	svc, repo := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, token := registerThenGetToken(t, svc)

	if err := svc.DeleteRegistration(context.Background(), clientID, token); err != nil {
		t.Fatalf("DeleteRegistration: %v", err)
	}
	if _, ok := repo.clients[clientID]; ok {
		t.Error("client must be removed from storage")
	}
}

func TestDeleteRegistration_NotFoundOnBadToken(t *testing.T) {
	svc, _ := newRegSvc(t, application.RegistrationServiceConfig{})
	clientID, _ := registerThenGetToken(t, svc)

	err := svc.DeleteRegistration(context.Background(), clientID, "wrong")
	regErr := registerErr(t, err)
	if regErr.Code != "not_found" {
		t.Errorf("code = %q", regErr.Code)
	}
}

func TestAuthorize_RejectsAdminCreatedClient(t *testing.T) {
	// A client whose RegistrationAccessTokenHash is empty was created
	// via the admin POST /clients route (or seeded at startup). The
	// RFC 7592 endpoints must return not_found rather than admit such
	// clients to management.
	svc, repo := newRegSvc(t, application.RegistrationServiceConfig{})
	repo.clients["admin-client"] = &domain.OAuthClient{
		ID:                          "admin-client",
		RegistrationAccessTokenHash: "",
	}

	_, err := svc.ReadRegistration(context.Background(), "admin-client", "any-token")
	regErr := registerErr(t, err)
	if regErr.Code != "not_found" {
		t.Errorf("code = %q", regErr.Code)
	}
}
