package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// stubValidator returns a canned token (with scopes) or an error.
type stubValidator struct {
	token *domain.Token
	err   error
}

func (s *stubValidator) Validate(context.Context, string) (*domain.Token, error) {
	return s.token, s.err
}

// stubClaims returns a canned UserClaims or error from GetUserClaims.
type stubClaims struct {
	resp *ports.UserClaims
	err  error
}

func (s *stubClaims) GetUserClaims(context.Context, string) (*ports.UserClaims, error) {
	return s.resp, s.err
}

func newUserInfoReq(t *testing.T, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestUserInfo_MissingAuthorizationHeader_Returns401(t *testing.T) {
	h := authhttp.NewUserInfoHandler(&stubValidator{}, &stubClaims{}, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, httptest.NewRequest(http.MethodGet, "/userinfo", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if !contains(w.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate header missing Bearer challenge: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestUserInfo_InvalidToken_Returns401WithInvalidToken(t *testing.T) {
	h := authhttp.NewUserInfoHandler(&stubValidator{err: errors.New("expired")}, &stubClaims{}, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, newUserInfoReq(t, "expired-token"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if !contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate missing error=invalid_token: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestUserInfo_MissingOpenIDScope_Returns403InsufficientScope(t *testing.T) {
	validator := &stubValidator{token: &domain.Token{Subject: "u-1", Scopes: []string{"read"}}}
	h := authhttp.NewUserInfoHandler(validator, &stubClaims{}, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, newUserInfoReq(t, "valid-token"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	wa := w.Header().Get("WWW-Authenticate")
	if !contains(wa, `error="insufficient_scope"`) || !contains(wa, `scope="openid"`) {
		t.Errorf("WWW-Authenticate missing insufficient_scope/openid: %q", wa)
	}
}

func TestUserInfo_NoClaimsFetcher_Returns503(t *testing.T) {
	validator := &stubValidator{token: &domain.Token{Subject: "u-1", Scopes: []string{"openid"}}}
	h := authhttp.NewUserInfoHandler(validator, nil, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, newUserInfoReq(t, "valid-token"))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestUserInfo_HappyPath_OpenIDOnly_ReturnsSubOnly(t *testing.T) {
	validator := &stubValidator{token: &domain.Token{Subject: "u-1", Scopes: []string{"openid"}}}
	claims := &stubClaims{resp: &ports.UserClaims{
		Subject: "u-1", Email: "alice@example.com", EmailVerified: true, Name: "Alice",
	}}
	h := authhttp.NewUserInfoHandler(validator, claims, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, newUserInfoReq(t, "valid-token"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["sub"] != "u-1" {
		t.Errorf("sub = %v, want u-1", body["sub"])
	}
	if _, ok := body["email"]; ok {
		t.Error("email present without email scope")
	}
	if _, ok := body["name"]; ok {
		t.Error("name present without profile scope")
	}
}

func TestUserInfo_HappyPath_EmailScope_ReturnsEmailFields(t *testing.T) {
	validator := &stubValidator{token: &domain.Token{Subject: "u-1", Scopes: []string{"openid", "email"}}}
	claims := &stubClaims{resp: &ports.UserClaims{
		Subject: "u-1", Email: "alice@example.com", EmailVerified: true,
	}}
	h := authhttp.NewUserInfoHandler(validator, claims, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, newUserInfoReq(t, "valid-token"))

	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["email"] != "alice@example.com" {
		t.Errorf("email = %v, want alice@example.com", body["email"])
	}
	if body["email_verified"] != true {
		t.Errorf("email_verified = %v, want true", body["email_verified"])
	}
}

func TestUserInfo_HappyPath_ProfileScope_ReturnsNameAndUpdatedAt(t *testing.T) {
	validator := &stubValidator{token: &domain.Token{Subject: "u-1", Scopes: []string{"openid", "profile"}}}
	claims := &stubClaims{resp: &ports.UserClaims{
		Subject: "u-1", Name: "Alice", UpdatedAt: 1750000000,
	}}
	h := authhttp.NewUserInfoHandler(validator, claims, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, newUserInfoReq(t, "valid-token"))

	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["name"] != "Alice" {
		t.Errorf("name = %v, want Alice", body["name"])
	}
	if got, _ := body["updated_at"].(float64); int64(got) != 1750000000 {
		t.Errorf("updated_at = %v, want 1750000000", body["updated_at"])
	}
}

func TestUserInfo_FetchNotFound_Returns401(t *testing.T) {
	// Subject from the token doesn't exist in identity-service anymore —
	// treated as invalid_token rather than 404 so the caller's bearer flow
	// sees the standard rejection.
	validator := &stubValidator{token: &domain.Token{Subject: "u-bogus", Scopes: []string{"openid"}}}
	claims := &stubClaims{err: apperrors.New(apperrors.ErrCodeNotFound, "user gone")}
	h := authhttp.NewUserInfoHandler(validator, claims, quietLogger())
	w := httptest.NewRecorder()
	h.Get(w, newUserInfoReq(t, "valid-token"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// contains is a tiny strings.Contains alias to keep test assertions terse.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
