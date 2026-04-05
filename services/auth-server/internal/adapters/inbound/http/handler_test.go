//go:build unit

package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// --- fakes ---

type fakeIssuer struct {
	resp *domain.GrantResponse
	err  error
}

func (f *fakeIssuer) IssueToken(_ context.Context, _ domain.GrantRequest) (*domain.GrantResponse, error) {
	return f.resp, f.err
}

type fakeIntrospector struct {
	resp *domain.IntrospectResponse
	err  error
}

func (f *fakeIntrospector) Introspect(_ context.Context, _ string) (*domain.IntrospectResponse, error) {
	return f.resp, f.err
}

type fakeRevoker struct {
	err error
}

func (f *fakeRevoker) Revoke(_ context.Context, _ string) error {
	return f.err
}

// --- helpers ---

func newTestHandler(t *testing.T, issuer *fakeIssuer, introspector *fakeIntrospector, revoker *fakeRevoker) *authhttp.Handler {
	t.Helper()
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(issuer, introspector, revoker, logger)
}

// postForm posts the given form values to the handler and returns the recorded response.
func postForm(t *testing.T, handler http.HandlerFunc, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func decodeOAuthError(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode oauth error body: %v", err)
	}
	return body
}

// --- Token endpoint ---

func TestToken_MissingGrantType_Returns400(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestToken_MissingClientID_Returns400(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_secret": {"s1"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestToken_MissingClientSecret_Returns400(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"c1"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestToken_SuccessfulIssuance_Returns200WithAccessToken(t *testing.T) {
	issuer := &fakeIssuer{resp: &domain.GrantResponse{
		AccessToken: "tok.abc",
		TokenType:   "bearer",
		ExpiresIn:   3600,
		Scope:       "read write",
	}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
		"scope":         {"read write"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d — body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp domain.GrantResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.AccessToken != "tok.abc" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "tok.abc")
	}
}

func TestToken_UnsupportedGrantType_Returns400WithOAuthError(t *testing.T) {
	issuer := &fakeIssuer{err: application.ErrUnsupportedGrantType}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"custom_grant"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %q, want %q", body["error"], "unsupported_grant_type")
	}
}

func TestToken_UnauthorizedError_Returns401WithWWWAuthenticate(t *testing.T) {
	// RFC 6749 §5.2: invalid_client must be 401 with WWW-Authenticate.
	issuer := &fakeIssuer{err: apperrors.New(apperrors.ErrCodeUnauthorized, "bad credentials")}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"bad"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401, got none")
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %q, want %q", body["error"], "invalid_client")
	}
}

func TestToken_ForbiddenError_Returns400WithInvalidScope(t *testing.T) {
	// RFC 6749 §5.2: invalid_scope must use HTTP 400, not 403.
	issuer := &fakeIssuer{err: apperrors.New(apperrors.ErrCodeForbidden, "scope not permitted")}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
		"scope":         {"admin"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (RFC 6749 §5.2: invalid_scope is 400)", w.Code, http.StatusBadRequest)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "invalid_scope" {
		t.Errorf("error = %q, want %q", body["error"], "invalid_scope")
	}
}

func TestToken_InternalError_Returns500WithServerError(t *testing.T) {
	issuer := &fakeIssuer{err: errors.New("unexpected db failure")}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "server_error" {
		t.Errorf("error = %q, want %q", body["error"], "server_error")
	}
}

func TestToken_CacheControlNoStore_OnErrorResponse(t *testing.T) {
	// RFC 6749 §5.1 requires Cache-Control: no-store on all token endpoint responses.
	issuer := &fakeIssuer{err: application.ErrUnsupportedGrantType}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"bad_grant"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestToken_CacheControlNoStore_OnSuccessResponse(t *testing.T) {
	// RFC 6749 §5.1: Cache-Control: no-store must be set on success responses too.
	issuer := &fakeIssuer{resp: &domain.GrantResponse{
		AccessToken: "tok.success",
		TokenType:   "bearer",
		ExpiresIn:   3600,
	}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

// --- Introspect endpoint ---

func TestIntrospect_MissingToken_Returns400(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Introspect, url.Values{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestIntrospect_ActiveToken_Returns200(t *testing.T) {
	introspector := &fakeIntrospector{resp: &domain.IntrospectResponse{
		Active:   true,
		ClientID: "c1",
		Subject:  "user-1",
	}}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{})
	w := postForm(t, h.Introspect, url.Values{"token": {"some.jwt.token"}})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d — body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp domain.IntrospectResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Active {
		t.Error("Active = false, want true")
	}
	if resp.ClientID != "c1" {
		t.Errorf("ClientID = %q, want %q", resp.ClientID, "c1")
	}
}

func TestIntrospect_InactiveToken_Returns200WithActiveFalse(t *testing.T) {
	introspector := &fakeIntrospector{resp: &domain.IntrospectResponse{Active: false}}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{})
	w := postForm(t, h.Introspect, url.Values{"token": {"expired.jwt"}})
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIntrospect_ServiceError_Returns500(t *testing.T) {
	introspector := &fakeIntrospector{err: errors.New("store unavailable")}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{})
	w := postForm(t, h.Introspect, url.Values{"token": {"some.jwt.token"}})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// --- Revoke endpoint ---

func TestRevoke_MissingToken_Returns400(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Revoke, url.Values{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRevoke_SuccessfulRevocation_Returns200(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	w := postForm(t, h.Revoke, url.Values{"token": {"tok.abc"}})
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRevoke_TokenNotFound_Returns200Idempotent(t *testing.T) {
	// RFC 7009 §2.2: revoking a non-existent or already-revoked token must return 200.
	revoker := &fakeRevoker{err: apperrors.New(apperrors.ErrCodeNotFound, "token not found")}
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, revoker)
	w := postForm(t, h.Revoke, url.Values{"token": {"already-revoked.tok"}})
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (RFC 7009 requires 200 for already-revoked token)", w.Code, http.StatusOK)
	}
}

func TestRevoke_InfrastructureError_Returns500(t *testing.T) {
	revoker := &fakeRevoker{err: errors.New("redis connection refused")}
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, revoker)
	w := postForm(t, h.Revoke, url.Values{"token": {"tok.abc"}})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// --- Authorize endpoint ---

func TestAuthorize_ReturnsNotImplemented(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	w := httptest.NewRecorder()
	h.Authorize(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotImplemented)
	}
}

// --- Health endpoint ---

func TestHealth_Returns200WithStatusOK(t *testing.T) {
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Health(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode health body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}
