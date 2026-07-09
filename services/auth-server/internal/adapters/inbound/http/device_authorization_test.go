//go:build unit

package http_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// fakeDeviceClientAuth returns a fixed client (with configurable grant
// types) or a fixed error, so tests can exercise both the "grant type
// not allowed" and "client authentication failed" branches independently
// of the shared fakeClientAuth (which always returns an empty-GrantTypes
// client — unsuitable here since HasGrantType would always be false).
type fakeDeviceClientAuth struct {
	client *domain.Client
	err    error
}

func (f *fakeDeviceClientAuth) Authenticate(_ context.Context, _, _ string) (*domain.Client, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

func deviceCapableClient(id string) *domain.Client {
	return &domain.Client{ID: id, GrantTypes: []domain.GrantType{domain.GrantTypeDeviceCode}}
}

// fakeDeviceAuthRepo implements domain.DeviceAuthorizationRepository,
// recording Save/Approve/Deny calls and optionally failing any of them.
type fakeDeviceAuthRepo struct {
	saveErr error
	saved   *domain.DeviceAuthorization

	approveErr       error
	approvedUserCode string
	approvedSubject  string

	denyErr        error
	deniedUserCode string
}

func (f *fakeDeviceAuthRepo) Save(_ context.Context, auth *domain.DeviceAuthorization) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = auth
	return nil
}

func (f *fakeDeviceAuthRepo) FindByDeviceCode(_ context.Context, _ string) (*domain.DeviceAuthorization, error) {
	return nil, domain.ErrDeviceAuthorizationNotFound
}

func (f *fakeDeviceAuthRepo) FindByUserCode(_ context.Context, _ string) (*domain.DeviceAuthorization, error) {
	return nil, domain.ErrDeviceAuthorizationNotFound
}

func (f *fakeDeviceAuthRepo) Approve(_ context.Context, userCode, subject string) error {
	if f.approveErr != nil {
		return f.approveErr
	}
	f.approvedUserCode = userCode
	f.approvedSubject = subject
	return nil
}

func (f *fakeDeviceAuthRepo) Deny(_ context.Context, userCode string) error {
	if f.denyErr != nil {
		return f.denyErr
	}
	f.deniedUserCode = userCode
	return nil
}

func (f *fakeDeviceAuthRepo) Consume(_ context.Context, _ string) (*domain.DeviceAuthorization, error) {
	return nil, domain.ErrDeviceAuthorizationNotFound
}

const testDeviceServiceToken = "test-device-service-token-1234567890"

func newTestDeviceAuthorizationHandler(clientAuth *fakeDeviceClientAuth, repo *fakeDeviceAuthRepo) *authhttp.DeviceAuthorizationHandler {
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewDeviceAuthorizationHandler(clientAuth, repo, "https://login-ui.example.com/device", time.Minute, 5, testDeviceServiceToken, logger)
}

func TestDeviceAuthorizationHandler_Success(t *testing.T) {
	// Arrange
	clientAuth := &fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}
	repo := &fakeDeviceAuthRepo{}
	h := newTestDeviceAuthorizationHandler(clientAuth, repo)

	form := url.Values{"client_id": {"cli-client"}, "scope": {"read"}}
	r := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.PostDeviceAuthorization(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.DeviceCode == "" {
		t.Error("expected non-empty device_code")
	}
	if len(resp.UserCode) != 9 || resp.UserCode[4] != '-' {
		t.Errorf("user_code = %q, want XXXX-XXXX shape", resp.UserCode)
	}
	if resp.VerificationURI != "https://login-ui.example.com/device" {
		t.Errorf("verification_uri = %q", resp.VerificationURI)
	}
	wantComplete := resp.VerificationURI + "?user_code=" + url.QueryEscape(resp.UserCode)
	if resp.VerificationURIComplete != wantComplete {
		t.Errorf("verification_uri_complete = %q, want %q", resp.VerificationURIComplete, wantComplete)
	}
	if resp.ExpiresIn != 60 {
		t.Errorf("expires_in = %d, want 60", resp.ExpiresIn)
	}
	if resp.Interval != 5 {
		t.Errorf("interval = %d, want 5", resp.Interval)
	}
	if repo.saved == nil {
		t.Fatal("expected repo.Save to be called")
	}
	if repo.saved.ClientID != "cli-client" || repo.saved.Scope != "read" {
		t.Errorf("saved record = %+v, want ClientID=cli-client Scope=read", repo.saved)
	}
	if repo.saved.Status != domain.DeviceAuthorizationPending {
		t.Errorf("saved.Status = %q, want pending", repo.saved.Status)
	}
}

func TestDeviceAuthorizationHandler_PublicClientNoSecretRequired(t *testing.T) {
	// Arrange — device flow clients are frequently public (CLIs); the
	// handler must not require a non-empty client_secret.
	clientAuth := &fakeDeviceClientAuth{client: deviceCapableClient("public-client")}
	repo := &fakeDeviceAuthRepo{}
	h := newTestDeviceAuthorizationHandler(clientAuth, repo)

	form := url.Values{"client_id": {"public-client"}}
	r := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.PostDeviceAuthorization(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
}

func TestDeviceAuthorizationHandler_MissingClientID(t *testing.T) {
	// Arrange
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("x")}, &fakeDeviceAuthRepo{})

	r := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.PostDeviceAuthorization(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDeviceAuthorizationHandler_ClientAuthenticationFailed(t *testing.T) {
	// Arrange
	clientAuth := &fakeDeviceClientAuth{err: fmt.Errorf("invalid credentials")}
	h := newTestDeviceAuthorizationHandler(clientAuth, &fakeDeviceAuthRepo{})

	form := url.Values{"client_id": {"cli-client"}, "client_secret": {"wrong"}}
	r := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.PostDeviceAuthorization(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestDeviceAuthorizationHandler_GrantTypeNotAllowedForClient(t *testing.T) {
	// Arrange — client registered without device_code in its grant types.
	clientAuth := &fakeDeviceClientAuth{client: &domain.Client{ID: "cli-client"}}
	h := newTestDeviceAuthorizationHandler(clientAuth, &fakeDeviceAuthRepo{})

	form := url.Values{"client_id": {"cli-client"}}
	r := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.PostDeviceAuthorization(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Error != "unauthorized_client" {
		t.Errorf("error = %q, want unauthorized_client", body.Error)
	}
}

func TestDeviceAuthorizationHandler_RepoSaveFailure(t *testing.T) {
	// Arrange
	clientAuth := &fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}
	repo := &fakeDeviceAuthRepo{saveErr: fmt.Errorf("store unavailable")}
	h := newTestDeviceAuthorizationHandler(clientAuth, repo)

	form := url.Values{"client_id": {"cli-client"}}
	r := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.PostDeviceAuthorization(w, r)

	// Assert
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDeviceAuthorizationHandler_ResponseHasNoStoreCacheControl(t *testing.T) {
	// Arrange — RFC 6749 §5.1's no-store requirement applies to every
	// token-adjacent endpoint that hands back credential material.
	clientAuth := &fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}
	h := newTestDeviceAuthorizationHandler(clientAuth, &fakeDeviceAuthRepo{})

	form := url.Values{"client_id": {"cli-client"}}
	r := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.PostDeviceAuthorization(w, r)

	// Assert
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}
