//go:build unit

package http_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// --- fakes ---

type fakeIssuer struct {
	resp *domain.GrantResponse
	err  error

	// lastReq captures the request IssueToken was called with, so tests
	// can assert which form fields the handler actually parsed into
	// domain.GrantRequest — this is what catches a field silently never
	// being wired from the HTTP layer.
	lastReq domain.GrantRequest
}

func (f *fakeIssuer) IssueToken(_ context.Context, req domain.GrantRequest) (*domain.GrantResponse, error) {
	f.lastReq = req
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

type fakeClientAuth struct {
	err error
	// client overrides the returned client's metadata (e.g. RedirectURIs,
	// Scopes) — nil keeps the original minimal default so every existing
	// caller of this fake is unaffected.
	client *domain.Client
}

func (f *fakeClientAuth) Authenticate(_ context.Context, _, _ string) (*domain.Client, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.client != nil {
		return f.client, nil
	}
	return &domain.Client{ID: "c1"}, nil
}

var _ ports.ClientAuthenticator = (*fakeClientAuth)(nil)

// --- helpers ---

func newTestHandler(t *testing.T, issuer *fakeIssuer, introspector *fakeIntrospector, revoker *fakeRevoker) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(issuer, introspector, revoker, &fakeClientAuth{}, logger, "", nil,
		application.NewDPoPValidator(memory.NewDPoPProofRepository()))
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

func TestToken_MissingRequiredField_Returns400(t *testing.T) {
	tests := []struct {
		name   string
		values url.Values
	}{
		{
			name: "missing grant_type",
			values: url.Values{
				"client_id":     {"c1"},
				"client_secret": {"s1"},
			},
		},
		{
			name: "missing client_id",
			values: url.Values{
				"grant_type":    {"client_credentials"},
				"client_secret": {"s1"},
			},
		},
		{
			name: "missing client_secret",
			values: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"c1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})

			// Act
			w := postForm(t, h.Token, tt.values)

			// Assert
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

// --- RFC 9449 DPoP (ADR-0025) ---

// buildValidDPoPProof signs a fresh ES256 DPoP proof for htm/htu, matching
// exactly what a real DPoP client would send at the token endpoint.
func buildValidDPoPProof(t *testing.T, htm, htu string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encoding EC public key: %v", err)
	}
	coordSize := (len(point) - 1) / 2
	enc := base64.RawURLEncoding.EncodeToString
	claims := jwt.MapClaims{
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   enc(point[1 : 1+coordSize]),
		"y":   enc(point[1+coordSize:]),
	}
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing proof: %v", err)
	}
	return signed
}

// postFormWithHeaders is postForm plus arbitrary extra request headers —
// needed for the DPoP header, which postForm has no parameter for.
func postFormWithHeaders(t *testing.T, handler http.HandlerFunc, values url.Values, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func TestToken_ValidDPoPHeader_SetsGrantRequestDPoPJKTAndReturnsDPoPTokenType(t *testing.T) {
	// Arrange — httptest.NewRequest's default Host is "example.com" and the
	// target path is "/", so the htu a real client would present is exactly
	// "http://example.com/" — requestURL(r) must reconstruct the same value
	// from the live request, not from any configured base URL.
	proof := buildValidDPoPProof(t, http.MethodPost, "http://example.com/")
	issuer := &fakeIssuer{resp: &domain.GrantResponse{AccessToken: "tok.abc", TokenType: "DPoP", ExpiresIn: 3600}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postFormWithHeaders(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	}, map[string]string{"DPoP": proof})

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if issuer.lastReq.DPoPJKT == "" {
		t.Error("expected a non-empty DPoPJKT on the issued GrantRequest")
	}
}

func TestToken_InvalidDPoPHeader_Returns400WithInvalidDPoPProofError(t *testing.T) {
	// Arrange — htu deliberately wrong, so DPoPValidator rejects it.
	proof := buildValidDPoPProof(t, http.MethodPost, "http://wrong-host.example.com/")
	issuer := &fakeIssuer{resp: &domain.GrantResponse{AccessToken: "tok.abc", TokenType: "Bearer", ExpiresIn: 3600}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postFormWithHeaders(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	}, map[string]string{"DPoP": proof})

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "invalid_dpop_proof" {
		t.Errorf(`error = %q, want "invalid_dpop_proof"`, body["error"])
	}
}

func TestToken_NoDPoPHeader_IssuesOrdinaryRequest(t *testing.T) {
	// Arrange — no DPoP header at all; must behave exactly as before this
	// feature existed.
	issuer := &fakeIssuer{resp: &domain.GrantResponse{AccessToken: "tok.abc", TokenType: "Bearer", ExpiresIn: 3600}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if issuer.lastReq.DPoPJKT != "" {
		t.Errorf("expected empty DPoPJKT with no DPoP header, got %q", issuer.lastReq.DPoPJKT)
	}
}

func TestToken_SuccessfulIssuance_Returns200WithAccessToken(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{resp: &domain.GrantResponse{
		AccessToken: "tok.abc",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "read write",
	}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
		"scope":         {"read write"},
	})

	// Assert
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

// TestToken_RefreshTokenGrant_PopulatesRefreshTokenField is a regression
// test for a bug where parseGrantRequest never read the "refresh_token"
// form field into domain.GrantRequest.RefreshToken — RefreshTokenStrategy
// reads that field to look up the presented token, so every refresh_token
// grant request failed via the real HTTP endpoint (masked as
// invalid_client/401, since FindByRaw("") returning not-found was
// classified as a client-auth failure) despite the grant being fully
// implemented and unit-tested at the application layer. No existing test
// exercised the HTTP parsing layer for this grant type before this one.
func TestToken_RefreshTokenGrant_PopulatesRefreshTokenField(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{resp: &domain.GrantResponse{AccessToken: "new.tok", TokenType: "Bearer"}}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
		"refresh_token": {"the-raw-refresh-token"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d — body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if issuer.lastReq.RefreshToken != "the-raw-refresh-token" {
		t.Errorf("GrantRequest.RefreshToken = %q, want %q", issuer.lastReq.RefreshToken, "the-raw-refresh-token")
	}
}

func TestToken_UnsupportedGrantType_Returns400WithOAuthError(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{err: application.ErrUnsupportedGrantType}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"custom_grant"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
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

	// Arrange
	issuer := &fakeIssuer{err: apperrors.New(apperrors.ErrCodeUnauthorized, "bad credentials")}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"bad"},
	})

	// Assert
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

	// Arrange
	issuer := &fakeIssuer{err: apperrors.New(apperrors.ErrCodeForbidden, "scope not permitted")}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
		"scope":         {"admin"},
	})

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d (RFC 6749 §5.2: invalid_scope is 400), want %d", w.Code, http.StatusBadRequest)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "invalid_scope" {
		t.Errorf("error = %q, want %q", body["error"], "invalid_scope")
	}
}

func TestToken_InternalError_Returns500WithServerError(t *testing.T) {
	// Arrange
	issuer := &fakeIssuer{err: errors.New("unexpected db failure")}
	h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Token, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "server_error" {
		t.Errorf("error = %q, want %q", body["error"], "server_error")
	}
}

func TestToken_CacheControlNoStore(t *testing.T) {
	// RFC 6749 §5.1 requires Cache-Control: no-store on all token endpoint responses.

	t.Run("error response", func(t *testing.T) {
		// Arrange
		issuer := &fakeIssuer{err: application.ErrUnsupportedGrantType}
		h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

		// Act
		w := postForm(t, h.Token, url.Values{
			"grant_type":    {"bad_grant"},
			"client_id":     {"c1"},
			"client_secret": {"s1"},
		})

		// Assert
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want %q", got, "no-store")
		}
	})

	t.Run("success response", func(t *testing.T) {
		// Arrange
		issuer := &fakeIssuer{resp: &domain.GrantResponse{
			AccessToken: "tok.success",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}}
		h := newTestHandler(t, issuer, &fakeIntrospector{}, &fakeRevoker{})

		// Act
		w := postForm(t, h.Token, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"c1"},
			"client_secret": {"s1"},
		})

		// Assert
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want %q", got, "no-store")
		}
	})
}

// --- Introspect endpoint ---

func TestIntrospect_MissingToken_Returns200Inactive(t *testing.T) {
	// RFC 7662 §2.2: the introspection endpoint must return 200 with {"active": false}
	// for a missing token — returning 400 would allow resource servers to misinterpret
	// the response as a transient error and allow the request through.

	// Arrange
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Introspect, url.Values{
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (RFC 7662 §2.2)", w.Code, http.StatusOK)
	}
	var resp domain.IntrospectResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Error("active = true, want false for missing token")
	}
}

func TestIntrospect_ActiveToken_Returns200(t *testing.T) {
	// Arrange
	introspector := &fakeIntrospector{resp: &domain.IntrospectResponse{
		Active:   true,
		ClientID: "c1",
		Subject:  "user-1",
	}}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{})

	// Act
	w := postForm(t, h.Introspect, url.Values{
		"token":         {"some.jwt.token"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
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
	// Arrange
	introspector := &fakeIntrospector{resp: &domain.IntrospectResponse{Active: false}}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{})

	// Act
	w := postForm(t, h.Introspect, url.Values{
		"token":         {"expired.jwt"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIntrospect_ServiceError_Returns200Inactive(t *testing.T) {
	// RFC 7662 §2.2: infrastructure errors must return 200 with {"active": false},
	// never a non-200 status. A non-200 could be misinterpreted by resource servers
	// as "service unavailable, allow through" instead of "token invalid, deny".

	// Arrange
	introspector := &fakeIntrospector{err: errors.New("store unavailable")}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{})

	// Act
	w := postForm(t, h.Introspect, url.Values{
		"token":         {"some.jwt.token"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp domain.IntrospectResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response body: %v", err)
	}
	if resp.Active {
		t.Error("active = true, want false on infrastructure error")
	}
}

func TestIntrospect_CacheControlNoStore(t *testing.T) {
	// RFC 7662 §2.4: introspection responses must not be cached.

	t.Run("infrastructure error path", func(t *testing.T) {
		// Arrange
		h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{err: errors.New("store down")}, &fakeRevoker{})

		// Act
		w := postForm(t, h.Introspect, url.Values{
			"token":         {"tok"},
			"client_id":     {"c1"},
			"client_secret": {"s1"},
		})

		// Assert
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
		}
	})

	t.Run("success path", func(t *testing.T) {
		// Arrange
		intro := &fakeIntrospector{resp: &domain.IntrospectResponse{Active: true}}
		h := newTestHandler(t, &fakeIssuer{}, intro, &fakeRevoker{})

		// Act
		w := postForm(t, h.Introspect, url.Values{
			"token":         {"tok"},
			"client_id":     {"c1"},
			"client_secret": {"s1"},
		})

		// Assert
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
		}
	})

	t.Run("missing token inactive path", func(t *testing.T) {
		// Arrange
		h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})

		// Act
		w := postForm(t, h.Introspect, url.Values{
			"client_id":     {"c1"},
			"client_secret": {"s1"},
		})

		// Assert
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
		}
	})
}

// --- Revoke endpoint ---

func TestRevoke_MissingToken_Returns400(t *testing.T) {
	// Arrange
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Revoke, url.Values{
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRevoke_SuccessfulRevocation_Returns200(t *testing.T) {
	// Arrange
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postForm(t, h.Revoke, url.Values{
		"token":         {"tok.abc"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRevoke_TokenNotFound_Returns200Idempotent(t *testing.T) {
	// RFC 7009 §2.2: revoking a non-existent or already-revoked token must return 200.

	// Arrange
	revoker := &fakeRevoker{err: apperrors.New(apperrors.ErrCodeNotFound, "token not found")}
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, revoker)

	// Act
	w := postForm(t, h.Revoke, url.Values{
		"token":         {"already-revoked.tok"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (RFC 7009 requires 200 for already-revoked token)", w.Code, http.StatusOK)
	}
}

func TestRevoke_InfrastructureError_Returns500WithRFC6749Body(t *testing.T) {
	// Arrange
	revoker := &fakeRevoker{err: errors.New("redis connection refused")}
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, revoker)

	// Act
	w := postForm(t, h.Revoke, url.Values{
		"token":         {"tok.abc"},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	})

	// Assert
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	body := decodeOAuthError(t, w)
	if body["error"] != "server_error" {
		t.Errorf("error = %q, want %q (RFC 6749 §5.2)", body["error"], "server_error")
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
}

// --- Audit emission (ADR-0018) ---

// captureSink records every audit event for verification.
type captureSink struct {
	events []audit.Event
	err    error
}

func (c *captureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

func TestIntrospect_EmitsTokenIntrospected_Active(t *testing.T) {
	introspector := &fakeIntrospector{resp: &domain.IntrospectResponse{
		Active:   true,
		ClientID: "rs-1",
		Subject:  "user-99",
		JTI:      "jti-xyz",
	}}
	sink := &captureSink{}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{}).
		WithAudit(audit.New(sink), "auth-server")

	_ = postForm(t, h.Introspect, url.Values{
		"token":         {"some.jwt.token"},
		"client_id":     {"caller-c1"},
		"client_secret": {"s1"},
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.EventType != "token_introspected" {
		t.Errorf("event_type = %q, want token_introspected", e.EventType)
	}
	if e.ActorID != "caller-c1" {
		t.Errorf("actor_id = %q, want caller-c1", e.ActorID)
	}
	if e.SubjectID != "user-99" {
		t.Errorf("subject_id = %q, want user-99", e.SubjectID)
	}
	if e.ResourceKind != audit.ResourceKindToken {
		t.Errorf("resource_kind = %q, want token", e.ResourceKind)
	}
	if e.ResourcePath != "auth-server/token/access" {
		t.Errorf("resource_path = %q, want auth-server/token/access", e.ResourcePath)
	}
	if active, _ := e.Attrs["active"].(bool); !active {
		t.Errorf("attrs.active = %v, want true", e.Attrs["active"])
	}
}

func TestIntrospect_EmitsTokenIntrospected_Inactive(t *testing.T) {
	introspector := &fakeIntrospector{resp: &domain.IntrospectResponse{Active: false}}
	sink := &captureSink{}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{}).
		WithAudit(audit.New(sink), "auth-server")

	_ = postForm(t, h.Introspect, url.Values{
		"token":         {"expired.jwt"},
		"client_id":     {"caller-c1"},
		"client_secret": {"s1"},
	})

	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	if active, _ := sink.events[0].Attrs["active"].(bool); active {
		t.Errorf("attrs.active = %v, want false", sink.events[0].Attrs["active"])
	}
}

func TestIntrospect_EmitFailure_ReturnsInactive(t *testing.T) {
	// Per ADR-0019: introspect must degrade safely (RFC 7662 §2.2 forbids
	// non-2xx) — audit-emit failure routes to the same active=false output.
	introspector := &fakeIntrospector{resp: &domain.IntrospectResponse{Active: true, Subject: "u"}}
	sink := &captureSink{err: errAuditTransport}
	h := newTestHandler(t, &fakeIssuer{}, introspector, &fakeRevoker{}).
		WithAudit(audit.New(sink), "auth-server")

	w := postForm(t, h.Introspect, url.Values{
		"token":         {"any.jwt"},
		"client_id":     {"caller-c1"},
		"client_secret": {"s1"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (RFC 7662 safe degrade)", w.Code)
	}
	var resp domain.IntrospectResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Errorf("Active = true on audit failure; expected safe-deny inactive")
	}
}

func TestRevoke_EmitsTokenRevoked(t *testing.T) {
	sink := &captureSink{}
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}).
		WithAudit(audit.New(sink), "auth-server")

	w := postForm(t, h.Revoke, url.Values{
		"token":           {"tok.abc"},
		"client_id":       {"caller-c1"},
		"client_secret":   {"s1"},
		"token_type_hint": {"access_token"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.EventType != "token_revoked" {
		t.Errorf("event_type = %q, want token_revoked", e.EventType)
	}
	if e.ActorID != "caller-c1" {
		t.Errorf("actor_id = %q, want caller-c1", e.ActorID)
	}
	if hint, _ := e.Attrs["token_type_hint"].(string); hint != "access_token" {
		t.Errorf("attrs.token_type_hint = %v, want access_token", e.Attrs["token_type_hint"])
	}
}

func TestRevoke_AuditFailure_Returns500(t *testing.T) {
	// Per ADR-0019: token_revoked is a paid event; an emit failure fails
	// the request so accounting cannot have gaps.
	sink := &captureSink{err: errAuditTransport}
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}).
		WithAudit(audit.New(sink), "auth-server")

	w := postForm(t, h.Revoke, url.Values{
		"token":         {"tok.abc"},
		"client_id":     {"caller-c1"},
		"client_secret": {"s1"},
	})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (ADR-0019 paid-event policy)", w.Code)
	}
}

func TestHandler_WithAudit_NilEmitterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}).
		WithAudit(nil, "auth-server")
}

var errAuditTransport = errors.New("simulated audit transport failure")

// --- Authorize endpoint ---

// fakeClientLookup satisfies ports.ClientLookup for /oauth/authorize tests.
type fakeClientLookup struct {
	clients map[string]*domain.Client
}

func (f *fakeClientLookup) Lookup(_ context.Context, clientID string) (*domain.Client, error) {
	c, ok := f.clients[clientID]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	return c, nil
}

// fakeChallengeRepo records the last Save call so the Authorize tests can
// inspect what got stored. Only Save is exercised here; the other methods
// satisfy the interface so the type compiles.
type fakeChallengeRepo struct {
	mu        sync.Mutex
	lastSaved *domain.LoginChallenge
	saveErr   error
}

func (f *fakeChallengeRepo) Save(_ context.Context, c *domain.LoginChallenge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.lastSaved = c
	return nil
}

func (f *fakeChallengeRepo) Get(_ context.Context, _ string) (*domain.LoginChallenge, error) {
	return nil, domain.ErrLoginChallengeNotFound
}

func (f *fakeChallengeRepo) Update(_ context.Context, _ *domain.LoginChallenge) error {
	return domain.ErrLoginChallengeNotFound
}

func (f *fakeChallengeRepo) Consume(_ context.Context, _ string) (*domain.LoginChallenge, error) {
	return nil, domain.ErrLoginChallengeNotFound
}

var _ domain.LoginChallengeRepository = (*fakeChallengeRepo)(nil)

// newAuthorizeTestHandler wires a Handler with a working AuthorizeConfig.
// The default lookup has a public client registered with one redirect URI
// and the openid+profile scopes; tests override the client map for negative
// cases.
func newAuthorizeTestHandler(t *testing.T, lookup *fakeClientLookup, repo *fakeChallengeRepo) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(
		&fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}, &fakeClientAuth{},
		logger, "",
		&authhttp.AuthorizeConfig{
			ClientLookup:  lookup,
			ChallengeRepo: repo,
			LoginUIURL:    "https://login.example.com",
			ChallengeTTL:  5 * time.Minute,
			Issuer:        "https://auth.example.com",
		},
		application.NewDPoPValidator(memory.NewDPoPProofRepository()),
	)
}

func newAuthorizeClient() *fakeClientLookup {
	return &fakeClientLookup{
		clients: map[string]*domain.Client{
			"client-a": {
				ID:           "client-a",
				Type:         domain.ClientTypePublic,
				RedirectURIs: []string{"https://rp.example.com/cb"},
				Scopes:       []string{"openid", "profile"},
				GrantTypes:   []domain.GrantType{domain.GrantTypeAuthorizationCode},
			},
		},
	}
}

func validAuthorizeQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"client-a"},
		"redirect_uri":          {"https://rp.example.com/cb"},
		"scope":                 {"openid profile"},
		"state":                 {"state-xyz"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"nonce":                 {"nonce-abc"},
	}
}

func TestAuthorize_HappyPath_RedirectsToLoginUIWithChallenge(t *testing.T) {
	// Arrange
	repo := &fakeChallengeRepo{}
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+validAuthorizeQuery().Encode(), nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	const want = "https://login.example.com/sign-in?login_challenge="
	if !strings.HasPrefix(loc, want) {
		t.Fatalf("Location = %q, want prefix %q", loc, want)
	}
	if repo.lastSaved == nil {
		t.Fatal("expected Save to be invoked")
	}
	saved := repo.lastSaved
	if saved.ClientID != "client-a" {
		t.Errorf("saved.ClientID = %q, want client-a", saved.ClientID)
	}
	if saved.RedirectURI != "https://rp.example.com/cb" {
		t.Errorf("saved.RedirectURI = %q, want %q", saved.RedirectURI, "https://rp.example.com/cb")
	}
	if saved.State != "state-xyz" {
		t.Errorf("saved.State = %q, want state-xyz", saved.State)
	}
	if saved.Nonce != "nonce-abc" {
		t.Errorf("saved.Nonce = %q, want nonce-abc", saved.Nonce)
	}
	if saved.CodeChallengeMethod != "S256" {
		t.Errorf("saved.CodeChallengeMethod = %q, want S256", saved.CodeChallengeMethod)
	}
	wantScopes := []string{"openid", "profile"}
	if len(saved.Scopes) != len(wantScopes) {
		t.Fatalf("saved.Scopes = %v, want %v", saved.Scopes, wantScopes)
	}
	for i, s := range wantScopes {
		if saved.Scopes[i] != s {
			t.Errorf("saved.Scopes[%d] = %q, want %q", i, saved.Scopes[i], s)
		}
	}
	if saved.ExpiresAt.Before(time.Now().Add(4 * time.Minute)) {
		t.Errorf("ExpiresAt = %v, want >= now+4m (TTL 5m)", saved.ExpiresAt)
	}
}

func TestAuthorize_UnknownClient_RendersErrorAndDoesNotRedirect(t *testing.T) {
	// Arrange — RFC 6749 §3.1.2.4 / §4.1.2.1: when the client_id is
	// unknown, the auth-server must NOT redirect back to the request's
	// redirect_uri (it could be attacker-controlled). Render the error.
	repo := &fakeChallengeRepo{}
	h := newAuthorizeTestHandler(t, &fakeClientLookup{clients: map[string]*domain.Client{}}, repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+validAuthorizeQuery().Encode(), nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want empty (must not redirect to attacker URI)", loc)
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite unknown client_id")
	}
}

func TestAuthorize_MismatchedRedirectURI_RendersErrorAndDoesNotRedirect(t *testing.T) {
	// Arrange — exact-match policy (ADR-0009 §"Redirect URI matching").
	// A mismatch means the request itself is suspect; render the error
	// rather than redirecting to a URI we have not validated.
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Set("redirect_uri", "https://attacker.example.com/cb")
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want empty", loc)
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite redirect_uri mismatch")
	}
}

func TestAuthorize_UnsupportedResponseType_RedirectsToClientWithError(t *testing.T) {
	// Arrange — RFC 6749 §4.1.2.1: once client_id + redirect_uri have
	// been validated, parameter errors are reported by redirecting to
	// the validated redirect_uri with ?error=&state=.
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Set("response_type", "token")
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.example.com/cb?") {
		t.Fatalf("Location = %q, want redirect back to client", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := u.Query().Get("error"); got != "unsupported_response_type" {
		t.Errorf("error = %q, want unsupported_response_type", got)
	}
	if got := u.Query().Get("state"); got != "state-xyz" {
		t.Errorf("state = %q, want state-xyz", got)
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite invalid response_type")
	}
}

func TestAuthorize_ErrorRedirect_IncludesIssuer(t *testing.T) {
	// Arrange — RFC 9207 §2: every authorization response, including the
	// early-error redirect this handler issues directly (as opposed to the
	// success path, which login-ui issues after the challenge handoff),
	// must carry `iss` so a client talking to more than one AS can detect
	// a mix-up attack.
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Set("response_type", "token")
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := u.Query().Get("iss"); got != "https://auth.example.com" {
		t.Errorf("iss = %q, want https://auth.example.com", got)
	}
}

func TestAuthorize_MissingPKCE_RedirectsToClientWithInvalidRequest(t *testing.T) {
	// Arrange — OAuth 2.1 + ADR-0009 mandate PKCE-S256 for every client.
	// A missing or non-S256 challenge must be rejected before a challenge
	// record is saved.
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Del("code_challenge")
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect-with-error", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	if got := u.Query().Get("error"); got != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", got)
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite missing code_challenge")
	}
}

func TestAuthorize_ScopeNotPermitted_RedirectsToClientWithInvalidScope(t *testing.T) {
	// Arrange — client is registered for openid+profile; request asks
	// for "email" too. Per RFC 6749 §5.2 the response code is
	// "invalid_scope" (redirected through the validated URI).
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Set("scope", "openid profile email")
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	if got := u.Query().Get("error"); got != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", got)
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite over-broad scope")
	}
}

func TestAuthorize_AuthorizationDetails_PersistedOnChallenge(t *testing.T) {
	// ADR-0017: a well-formed RFC 9396 `authorization_details` array on
	// /oauth/authorize must land on the LoginChallenge byte-for-byte so
	// the granted-details flow through to the issued token at
	// /oauth/token without an extra parse hop.
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Set("authorization_details", `[{"type":"mcp_tool","tool":"get_standings"}]`)
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", w.Code, w.Body.String())
	}
	if repo.lastSaved == nil {
		t.Fatal("expected Save to be invoked")
	}
	if len(repo.lastSaved.AuthorizationDetails) != 1 {
		t.Fatalf("AuthorizationDetails len = %d, want 1", len(repo.lastSaved.AuthorizationDetails))
	}
	if repo.lastSaved.AuthorizationDetails[0].Type != domain.AuthorizationDetailTypeMCPTool {
		t.Errorf("Type = %q, want mcp_tool", repo.lastSaved.AuthorizationDetails[0].Type)
	}
}

func TestAuthorize_AcrValues_PersistedOnChallenge(t *testing.T) {
	// ADR-0024: acr_values is parsed and stored on the LoginChallenge for
	// protocol completeness, mirroring how prompt/max_age already land
	// there.
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Set("acr_values", "pwd urn:example:mfa")
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", w.Code, w.Body.String())
	}
	if repo.lastSaved == nil {
		t.Fatal("expected Save to be invoked")
	}
	want := []string{"pwd", "urn:example:mfa"}
	if !slices.Equal(repo.lastSaved.AcrValues, want) {
		t.Errorf("AcrValues = %v, want %v", repo.lastSaved.AcrValues, want)
	}
}

func TestAuthorize_MalformedAuthorizationDetails_RedirectsWithInvalidAuthorizationDetails(t *testing.T) {
	// RFC 9396 §5: a malformed authorization_details parameter must be
	// reported via the same redirect-based error channel as the other
	// authorize-time errors, with code `invalid_authorization_details`.
	repo := &fakeChallengeRepo{}
	q := validAuthorizeQuery()
	q.Set("authorization_details", `not-a-json-array`)
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	if got := u.Query().Get("error"); got != "invalid_authorization_details" {
		t.Errorf("error = %q, want invalid_authorization_details", got)
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite malformed authorization_details")
	}
}

func TestAuthorize_OmittedAuthorizationDetails_PersistsNilSlice(t *testing.T) {
	// Backwards compatibility — RFC 9396 §2 makes the parameter optional.
	// Existing OAuth clients that have never heard of RAR must continue
	// to authorize successfully with no granted-details on the challenge.
	repo := &fakeChallengeRepo{}
	h := newAuthorizeTestHandler(t, newAuthorizeClient(), repo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+validAuthorizeQuery().Encode(), nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", w.Code, w.Body.String())
	}
	if repo.lastSaved == nil {
		t.Fatal("expected Save to be invoked")
	}
	if repo.lastSaved.AuthorizationDetails != nil {
		t.Errorf("AuthorizationDetails = %v, want nil when omitted", repo.lastSaved.AuthorizationDetails)
	}
}

// --- /internal/issue-code ---

// fakeChallengeReader is a LoginChallengeRepository whose Consume returns a
// pre-seeded challenge. Used by IssueCode tests to control which challenge
// is redeemed.
type fakeChallengeReader struct {
	mu          sync.Mutex
	seeded      *domain.LoginChallenge
	consumeErr  error
	consumedKey string
}

func (f *fakeChallengeReader) Save(_ context.Context, _ *domain.LoginChallenge) error { return nil }
func (f *fakeChallengeReader) Get(_ context.Context, _ string) (*domain.LoginChallenge, error) {
	return nil, domain.ErrLoginChallengeNotFound
}
func (f *fakeChallengeReader) Update(_ context.Context, _ *domain.LoginChallenge) error {
	return domain.ErrLoginChallengeNotFound
}
func (f *fakeChallengeReader) Consume(_ context.Context, id string) (*domain.LoginChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumedKey = id
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	if f.seeded == nil {
		return nil, domain.ErrLoginChallengeNotFound
	}
	return f.seeded, nil
}

var _ domain.LoginChallengeRepository = (*fakeChallengeReader)(nil)

// fakeAuthCodeIssuer satisfies ports.AuthorizationCodeIssuer for IssueCode
// tests. Records the IssueCodeRequest so assertions can inspect what the
// handler passed through.
type fakeAuthCodeIssuer struct {
	mu         sync.Mutex
	lastReq    ports.IssueCodeRequest
	codeToMint string
	err        error
}

func (f *fakeAuthCodeIssuer) Issue(_ context.Context, req ports.IssueCodeRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReq = req
	if f.err != nil {
		return "", f.err
	}
	return f.codeToMint, nil
}

var _ ports.AuthorizationCodeIssuer = (*fakeAuthCodeIssuer)(nil)

func storedChallenge() *domain.LoginChallenge {
	return &domain.LoginChallenge{
		ID:                  "ch-1",
		ClientID:            "client-a",
		RedirectURI:         "https://rp.example.com/cb",
		Scopes:              []string{"openid", "profile"},
		State:               "state-xyz",
		Nonce:               "nonce-abc",
		CodeChallenge:       "code-chal-value",
		CodeChallengeMethod: "S256",
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}
}

func newIssueCodeHandler(t *testing.T, repo *fakeChallengeReader, issuer *fakeAuthCodeIssuer) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(
		&fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}, &fakeClientAuth{},
		logger, "",
		&authhttp.AuthorizeConfig{
			ClientLookup:    newAuthorizeClient(),
			ChallengeRepo:   repo,
			LoginUIURL:      "https://login.example.com",
			ChallengeTTL:    5 * time.Minute,
			AuthCodeIssuer:  issuer,
			IssueCodeBearer: "service-token-secret",
			Issuer:          "https://auth.example.com",
		},
		application.NewDPoPValidator(memory.NewDPoPProofRepository()),
	)
}

func postIssueCode(t *testing.T, h *authhttp.Handler, bearer string, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/internal/issue-code", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.IssueCode(w, r)
	return w
}

func TestIssueCode_HappyPath_Returns200WithCode(t *testing.T) {
	// Arrange
	repo := &fakeChallengeReader{seeded: storedChallenge()}
	issuer := &fakeAuthCodeIssuer{codeToMint: "minted-code-abc"}
	h := newIssueCodeHandler(t, repo, issuer)
	body := `{"login_challenge":"ch-1","session_id":"user-42","consent_granted":["openid","profile"]}`

	// Act
	w := postIssueCode(t, h, "service-token-secret", body)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["code"] != "minted-code-abc" {
		t.Errorf("code = %q, want minted-code-abc", resp["code"])
	}
	if resp["redirect_uri"] != "https://rp.example.com/cb" {
		t.Errorf("redirect_uri = %q, want %q", resp["redirect_uri"], "https://rp.example.com/cb")
	}
	if resp["state"] != "state-xyz" {
		t.Errorf("state = %q, want state-xyz", resp["state"])
	}
	if repo.consumedKey != "ch-1" {
		t.Errorf("Consume key = %q, want ch-1", repo.consumedKey)
	}
	if issuer.lastReq.ClientID != "client-a" || issuer.lastReq.Subject != "user-42" {
		t.Errorf("IssueCodeRequest = %+v", issuer.lastReq)
	}
	if issuer.lastReq.Nonce != "nonce-abc" {
		t.Errorf("Nonce = %q, want nonce-abc (must propagate from challenge)", issuer.lastReq.Nonce)
	}
	if issuer.lastReq.CodeChallengeMethod != "S256" {
		t.Errorf("CodeChallengeMethod = %q, want S256", issuer.lastReq.CodeChallengeMethod)
	}
	if resp["iss"] != "https://auth.example.com" {
		t.Errorf("iss = %q, want https://auth.example.com — RFC 9207 §2 requires it on every authorization response,"+
			" and login-ui's success redirect is built from this field", resp["iss"])
	}
}

func TestIssueCode_MissingBearer_Returns401(t *testing.T) {
	// Arrange
	repo := &fakeChallengeReader{seeded: storedChallenge()}
	h := newIssueCodeHandler(t, repo, &fakeAuthCodeIssuer{})

	// Act
	w := postIssueCode(t, h, "", `{"login_challenge":"ch-1","session_id":"user-42","consent_granted":["openid"]}`)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if repo.consumedKey != "" {
		t.Error("Consume was called despite missing bearer")
	}
}

func TestIssueCode_WrongBearer_Returns401(t *testing.T) {
	// Arrange
	repo := &fakeChallengeReader{seeded: storedChallenge()}
	h := newIssueCodeHandler(t, repo, &fakeAuthCodeIssuer{})

	// Act
	w := postIssueCode(t, h, "wrong-secret", `{"login_challenge":"ch-1","session_id":"user-42","consent_granted":["openid"]}`)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if repo.consumedKey != "" {
		t.Error("Consume was called despite wrong bearer")
	}
}

func TestIssueCode_UnknownChallenge_Returns400(t *testing.T) {
	// Arrange — Consume reports NotFound. /internal/issue-code maps this to
	// 400 rather than 404 because the caller (login-ui) treats the error
	// as "redirect failed" rather than "resource missing".
	repo := &fakeChallengeReader{consumeErr: domain.ErrLoginChallengeNotFound}
	h := newIssueCodeHandler(t, repo, &fakeAuthCodeIssuer{})

	// Act
	w := postIssueCode(t, h, "service-token-secret", `{"login_challenge":"missing","session_id":"u","consent_granted":["openid"]}`)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestIssueCode_ConsentNotSubsetOfScopes_Returns400(t *testing.T) {
	// Arrange — challenge requested openid+profile; consent_granted has
	// "email" too, which the user could not legitimately have granted.
	repo := &fakeChallengeReader{seeded: storedChallenge()}
	h := newIssueCodeHandler(t, repo, &fakeAuthCodeIssuer{codeToMint: "x"})

	// Act
	w := postIssueCode(t, h, "service-token-secret", `{"login_challenge":"ch-1","session_id":"u","consent_granted":["openid","profile","email"]}`)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestIssueCode_MalformedJSON_Returns400(t *testing.T) {
	// Arrange
	repo := &fakeChallengeReader{seeded: storedChallenge()}
	h := newIssueCodeHandler(t, repo, &fakeAuthCodeIssuer{})

	// Act
	w := postIssueCode(t, h, "service-token-secret", `{not json}`)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if repo.consumedKey != "" {
		t.Error("Consume was called despite invalid body")
	}
}

func TestIssueCode_ForwardsAuthorizationDetailsFromChallenge(t *testing.T) {
	// ADR-0017: granted-details captured at /oauth/authorize must
	// follow the LoginChallenge onto the IssueCodeRequest so the
	// AuthorizationCode (and the eventual token) carry the same
	// per-call permissions the agent originally requested.
	challenge := storedChallenge()
	challenge.AuthorizationDetails = []domain.AuthorizationDetail{
		{Type: domain.AuthorizationDetailTypeMCPTool, Raw: []byte(`{"type":"mcp_tool","tool":"get_standings"}`)},
	}
	repo := &fakeChallengeReader{seeded: challenge}
	issuer := &fakeAuthCodeIssuer{codeToMint: "minted-code-abc"}
	h := newIssueCodeHandler(t, repo, issuer)
	body := `{"login_challenge":"ch-1","session_id":"user-42","consent_granted":["openid","profile"]}`

	w := postIssueCode(t, h, "service-token-secret", body)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if len(issuer.lastReq.AuthorizationDetails) != 1 {
		t.Fatalf("IssueCodeRequest.AuthorizationDetails len = %d, want 1", len(issuer.lastReq.AuthorizationDetails))
	}
	if issuer.lastReq.AuthorizationDetails[0].Type != domain.AuthorizationDetailTypeMCPTool {
		t.Errorf("Type = %q, want mcp_tool", issuer.lastReq.AuthorizationDetails[0].Type)
	}
}

func TestIssueCode_NilConfig_Returns404(t *testing.T) {
	// Arrange — when AuthorizeConfig is nil, the endpoint is not advertised.
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postIssueCode(t, h, "any", `{}`)

	// Assert
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAuthorize_NilConfig_StillReturnsNotImplemented(t *testing.T) {
	// Arrange — passing nil AuthorizeConfig preserves the original stub.
	// Test seams (and the introspect-only handler tests) do not have to
	// wire the authorize subsystem just to compile.
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotImplemented)
	}
}

// --- POST /oauth/par (RFC 9126) ---

// fakePARRepo is a minimal domain.PushedAuthorizationRequestRepository
// double: Save records the last saved request, Consume returns whatever
// the test configured.
type fakePARRepo struct {
	mu          sync.Mutex
	lastSaved   *domain.PushedAuthorizationRequest
	saveErr     error
	consumeResp *domain.PushedAuthorizationRequest
	consumeErr  error
}

func (f *fakePARRepo) Save(_ context.Context, req *domain.PushedAuthorizationRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.lastSaved = req
	return nil
}

func (f *fakePARRepo) Consume(_ context.Context, _ string) (*domain.PushedAuthorizationRequest, error) {
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	return f.consumeResp, nil
}

func parClient() *domain.Client {
	return &domain.Client{
		ID:           "client-a",
		Type:         domain.ClientTypeConfidential,
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"read", "write"},
		GrantTypes:   []domain.GrantType{domain.GrantTypeAuthorizationCode},
	}
}

func newPARTestHandler(t *testing.T, clientAuth *fakeClientAuth, parRepo *fakePARRepo) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(
		&fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}, clientAuth,
		logger, "",
		&authhttp.AuthorizeConfig{
			ClientLookup: &fakeClientLookup{clients: map[string]*domain.Client{"client-a": parClient()}},
			PARRepo:      parRepo,
			PARTTL:       90 * time.Second,
		},
		application.NewDPoPValidator(memory.NewDPoPProofRepository()),
	)
}

func postPAR(t *testing.T, h *authhttp.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/oauth/par", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.PushAuthorize(w, r)
	return w
}

func validPARForm() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"client-a"},
		"client_secret":         {"whatever"},
		"redirect_uri":          {"https://rp.example.com/cb"},
		"scope":                 {"read"},
		"state":                 {"state-xyz"},
		"code_challenge":        {"challenge-value"},
		"code_challenge_method": {"S256"},
	}
}

func TestPushAuthorize_HappyPath_Returns201WithRequestURI(t *testing.T) {
	// Arrange
	repo := &fakePARRepo{}
	h := newPARTestHandler(t, &fakeClientAuth{client: parClient()}, repo)

	// Act
	w := postPAR(t, h, validPARForm())

	// Assert
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	requestURI, _ := resp["request_uri"].(string)
	if !strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri = %q, want urn:ietf:params:oauth:request_uri: prefix", requestURI)
	}
	if resp["expires_in"] != float64(90) {
		t.Errorf("expires_in = %v, want 90", resp["expires_in"])
	}
	if repo.lastSaved == nil {
		t.Fatal("Save was not called")
	}
	if repo.lastSaved.ClientID != "client-a" || repo.lastSaved.RedirectURI != "https://rp.example.com/cb" {
		t.Errorf("saved request = %+v", repo.lastSaved)
	}
}

func TestPushAuthorize_InvalidClient_Returns401(t *testing.T) {
	// Arrange
	repo := &fakePARRepo{}
	h := newPARTestHandler(t, &fakeClientAuth{err: apperrors.New(apperrors.ErrCodeUnauthorized, "bad secret")}, repo)

	// Act
	w := postPAR(t, h, validPARForm())

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite failed client authentication")
	}
}

func TestPushAuthorize_MissingPKCE_Returns400(t *testing.T) {
	// Arrange
	repo := &fakePARRepo{}
	h := newPARTestHandler(t, &fakeClientAuth{client: parClient()}, repo)
	form := validPARForm()
	form.Del("code_challenge")

	// Act
	w := postPAR(t, h, form)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", resp["error"])
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite missing code_challenge")
	}
}

func TestPushAuthorize_UnregisteredRedirectURI_Returns400(t *testing.T) {
	// Arrange
	repo := &fakePARRepo{}
	h := newPARTestHandler(t, &fakeClientAuth{client: parClient()}, repo)
	form := validPARForm()
	form.Set("redirect_uri", "https://attacker.example.com/cb")

	// Act
	w := postPAR(t, h, form)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
	if repo.lastSaved != nil {
		t.Error("Save was invoked despite an unregistered redirect_uri")
	}
}

func TestPushAuthorize_NilConfig_Returns501(t *testing.T) {
	// Arrange
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})

	// Act
	w := postPAR(t, h, validPARForm())

	// Assert
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotImplemented)
	}
}

// --- GET /oauth/authorize?request_uri=... (RFC 9126 §4) ---

func TestAuthorize_WithRequestURI_HappyPath_RedirectsToLoginUIWithChallenge(t *testing.T) {
	// Arrange
	challengeRepo := &fakeChallengeRepo{}
	parRepo := &fakePARRepo{consumeResp: &domain.PushedAuthorizationRequest{
		RequestURI:          "urn:ietf:params:oauth:request_uri:abc",
		ClientID:            "client-a",
		ResponseType:        "code",
		RedirectURI:         "https://rp.example.com/cb",
		Scope:               "read",
		State:               "state-xyz",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
	}}
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(
		&fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}, &fakeClientAuth{},
		logger, "",
		&authhttp.AuthorizeConfig{
			ClientLookup:  &fakeClientLookup{clients: map[string]*domain.Client{"client-a": parClient()}},
			ChallengeRepo: challengeRepo,
			LoginUIURL:    "https://login.example.com",
			ChallengeTTL:  5 * time.Minute,
			PARRepo:       parRepo,
			PARTTL:        90 * time.Second,
		},
		application.NewDPoPValidator(memory.NewDPoPProofRepository()),
	)
	r := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:abc&client_id=client-a", nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://login.example.com/sign-in?login_challenge=") {
		t.Errorf("Location = %q, want redirect to login-ui", loc)
	}
	if challengeRepo.lastSaved == nil {
		t.Fatal("LoginChallenge was not saved")
	}
	if challengeRepo.lastSaved.RedirectURI != "https://rp.example.com/cb" || challengeRepo.lastSaved.State != "state-xyz" {
		t.Errorf("saved challenge = %+v, want fields sourced from the pushed request", challengeRepo.lastSaved)
	}
}

func TestAuthorize_WithRequestURI_UnknownRequestURI_Returns400(t *testing.T) {
	// Arrange
	parRepo := &fakePARRepo{consumeErr: domain.ErrPushedAuthorizationRequestNotFound}
	h := newPARTestHandler(t, &fakeClientAuth{}, parRepo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?request_uri=urn:unknown&client_id=client-a", nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAuthorize_WithRequestURI_ClientIDMismatch_Returns400(t *testing.T) {
	// Arrange — RFC 9126 §4's anti-injection binding: the query's client_id
	// must match the client_id the request_uri was pushed under.
	parRepo := &fakePARRepo{consumeResp: &domain.PushedAuthorizationRequest{
		RequestURI: "urn:ietf:params:oauth:request_uri:abc",
		ClientID:   "client-a",
	}}
	h := newPARTestHandler(t, &fakeClientAuth{}, parRepo)
	r := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:abc&client_id=client-b", nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAuthorize_WithRequestURI_MissingClientID_Returns400(t *testing.T) {
	// Arrange
	parRepo := &fakePARRepo{}
	h := newPARTestHandler(t, &fakeClientAuth{}, parRepo)
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:abc", nil)
	w := httptest.NewRecorder()

	// Act
	h.Authorize(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// --- Introspect with pre-shared secret ---

func newTestHandlerWithSecret(t *testing.T, issuer *fakeIssuer, introspector *fakeIntrospector, revoker *fakeRevoker, secret string) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(issuer, introspector, revoker, &fakeClientAuth{}, logger, secret, nil,
		application.NewDPoPValidator(memory.NewDPoPProofRepository()))
}

func TestIntrospect_WithSecret_CorrectSecret_Returns200(t *testing.T) {
	// Arrange
	intro := &fakeIntrospector{resp: &domain.IntrospectResponse{Active: true, ClientID: "c1"}}
	h := newTestHandlerWithSecret(t, &fakeIssuer{}, intro, &fakeRevoker{}, "test-secret")
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {"tok"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()

	// Act
	h.Introspect(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIntrospect_WithSecret_WrongSecret_Returns401WithBearerChallenge(t *testing.T) {
	// Arrange
	h := newTestHandlerWithSecret(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}, "correct-secret")
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {"tok"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer wrong-secret")
	w := httptest.NewRecorder()

	// Act
	h.Introspect(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if wwa := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wwa, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q, want Bearer challenge", wwa)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q (RFC 7662 §2.4)", cc, "no-store")
	}
}

func TestIntrospect_WithSecret_MissingHeader_Returns401(t *testing.T) {
	// Arrange
	h := newTestHandlerWithSecret(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{}, "secret")
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {"tok"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.Introspect(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- Health endpoint ---

func TestHealth_Returns200WithStatusOK(t *testing.T) {
	// Arrange
	h := newTestHandler(t, &fakeIssuer{}, &fakeIntrospector{}, &fakeRevoker{})
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	// Act
	h.Health(w, r)

	// Assert
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
