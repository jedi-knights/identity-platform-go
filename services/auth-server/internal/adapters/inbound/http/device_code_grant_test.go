//go:build unit

package http_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestToken_DeviceCodeGrant_AuthorizationPending(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{err: &application.DevicePollError{Code: "authorization_pending"}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":  {string(domain.GrantTypeDeviceCode)},
		"client_id":   {"cli-client"},
		"device_code": {"device-abc"},
	})

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "authorization_pending" {
		t.Errorf("error = %q, want %q", body["error"], "authorization_pending")
	}
}

func TestToken_DeviceCodeGrant_AccessDenied(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{err: &application.DevicePollError{Code: "access_denied"}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":  {string(domain.GrantTypeDeviceCode)},
		"client_id":   {"cli-client"},
		"device_code": {"device-abc"},
	})

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "access_denied" {
		t.Errorf("error = %q, want %q", body["error"], "access_denied")
	}
}

func TestToken_DeviceCodeGrant_ExpiredToken(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{err: &application.DevicePollError{Code: "expired_token"}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":  {string(domain.GrantTypeDeviceCode)},
		"client_id":   {"cli-client"},
		"device_code": {"device-abc"},
	})

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "expired_token" {
		t.Errorf("error = %q, want %q", body["error"], "expired_token")
	}
}

func TestToken_DeviceCodeGrant_PublicClientNoSecretRequired(t *testing.T) {
	// Arrange — device flow clients are frequently public (CLIs); the
	// token endpoint must not require a non-empty client_secret for this
	// grant type, mirroring the same carve-out token-exchange already has.
	issuer := &fakeIssuer{resp: &domain.GrantResponse{AccessToken: "tok", TokenType: "Bearer"}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":  {string(domain.GrantTypeDeviceCode)},
		"client_id":   {"public-cli-client"},
		"device_code": {"device-abc"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if issuer.lastReq.DeviceCode != "device-abc" {
		t.Errorf("issuer received DeviceCode = %q, want device-abc", issuer.lastReq.DeviceCode)
	}
	if issuer.lastReq.GrantType != domain.GrantTypeDeviceCode {
		t.Errorf("issuer received GrantType = %q, want %q", issuer.lastReq.GrantType, domain.GrantTypeDeviceCode)
	}
}
