//go:build unit

package http_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// TestToken_ClientAssertion_WaivesClientSecretRequirement covers RFC 7523
// §2.2's JWT-bearer client authentication parameters (ADR-0023). The token
// endpoint must not reject the request for a missing client_secret when a
// client_assertion of the correct type is present — verification of the
// assertion itself is the grant strategy's job, not the HTTP layer's.
func TestToken_ClientAssertion_WaivesClientSecretRequirement(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{resp: &domain.GrantResponse{AccessToken: "tok", TokenType: "Bearer"}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {"jwt-bearer-client"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {"header.payload.signature"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if issuer.lastReq.ClientAssertion != "header.payload.signature" {
		t.Errorf("ClientAssertion = %q", issuer.lastReq.ClientAssertion)
	}
	if issuer.lastReq.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("ClientAssertionType = %q", issuer.lastReq.ClientAssertionType)
	}
}

// TestToken_ClientAssertion_WrongTypeStillRequiresSecret confirms the
// waiver is scoped to exactly the jwt-bearer URN — an unrecognised
// client_assertion_type must not also waive the secret requirement.
func TestToken_ClientAssertion_WrongTypeStillRequiresSecret(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{resp: &domain.GrantResponse{AccessToken: "tok", TokenType: "Bearer"}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {"some-client"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:saml2-bearer"},
		"client_assertion":      {"some-assertion"},
	})

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
