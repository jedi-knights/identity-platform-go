//go:build unit

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/testutil"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// --- fakes ---

type fakeIntrospector struct {
	result *ports.IntrospectionResult
	err    error
}

func (f *fakeIntrospector) Introspect(_ context.Context, _ string) (*ports.IntrospectionResult, error) {
	return f.result, f.err
}

// --- helpers ---

// okHandler is a trivial next handler that records whether it was called.
func okHandler(t *testing.T, called *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

// signHS256 creates a minimal HS256-signed JWT with the given claims.
// ExpiresAt is optional — omitting it produces a non-expiring token, which is
// fine for tests that are not checking expiry behaviour.
func signHS256(t *testing.T, key []byte, claims jwtClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing test token: %v", err)
	}
	return raw
}

func bearerRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// --- extractBearer ---

func TestExtractBearer_MissingHeader_Returns401(t *testing.T) {
	// Arrange
	r := httptest.NewRequest(http.MethodGet, "/resources", nil) // no Authorization header
	w := httptest.NewRecorder()

	// Act
	_, ok := extractBearer(w, r)

	// Assert
	if ok {
		t.Error("extractBearer returned ok=true for missing header, want false")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestExtractBearer_MalformedHeader_Returns401(t *testing.T) {
	// Arrange
	// "Token xyz" is not a valid Bearer header.
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r.Header.Set("Authorization", "Token xyz")
	w := httptest.NewRecorder()

	// Act
	_, ok := extractBearer(w, r)

	// Assert
	if ok {
		t.Error("extractBearer returned ok=true for wrong scheme, want false")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestExtractBearer_WhitespaceOnlyToken_Returns401(t *testing.T) {
	// Arrange
	// "Bearer   " (spaces after "Bearer ") must be rejected, not forwarded as a token.
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r.Header.Set("Authorization", "Bearer   ")
	w := httptest.NewRecorder()

	// Act
	_, ok := extractBearer(w, r)

	// Assert
	if ok {
		t.Error("extractBearer returned ok=true for whitespace-only token, want false")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestExtractBearer_EmptyToken_Returns401(t *testing.T) {
	// Arrange
	// "Bearer " with nothing after it is not a valid token.
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	// Act
	_, ok := extractBearer(w, r)

	// Assert
	if ok {
		t.Error("extractBearer returned ok=true for empty token, want false")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestExtractBearer_ValidToken_ReturnsToken(t *testing.T) {
	// Arrange
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r.Header.Set("Authorization", "Bearer my.jwt.token")
	w := httptest.NewRecorder()

	// Act
	raw, ok := extractBearer(w, r)

	// Assert
	if !ok {
		t.Error("extractBearer returned ok=false for valid Bearer header, want true")
	}
	if raw != "my.jwt.token" {
		t.Errorf("raw = %q, want %q", raw, "my.jwt.token")
	}
}

// --- IntrospectionAuthMiddleware ---

func TestIntrospectionAuthMiddleware_ActiveToken_CallsNext(t *testing.T) {
	// Arrange
	result := &ports.IntrospectionResult{
		Active:   true,
		Subject:  "user-1",
		ClientID: "c1",
		Scope:    "read write",
	}
	var called bool
	mw := IntrospectionAuthMiddleware(&fakeIntrospector{result: result}, testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, "valid.jwt"))

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called for an active token")
	}
}

func TestIntrospectionAuthMiddleware_InactiveToken_Returns401WithInvalidToken(t *testing.T) {
	// Arrange
	result := &ports.IntrospectionResult{Active: false}
	var called bool
	mw := IntrospectionAuthMiddleware(&fakeIntrospector{result: result}, testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, "revoked.jwt"))

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called for an inactive token")
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("expected WWW-Authenticate header for inactive token")
	}
	// RFC 6750: error="invalid_token" for inactive/revoked tokens.
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain error=\"invalid_token\"", wwwAuth)
	}
}

func TestIntrospectionAuthMiddleware_ServiceError_Returns500(t *testing.T) {
	// Arrange
	introspector := &fakeIntrospector{err: apperrors.New(apperrors.ErrCodeInternal, "introspection unavailable")}
	var called bool
	mw := IntrospectionAuthMiddleware(introspector, testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, "some.jwt"))

	// Assert
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if called {
		t.Error("next handler must not be called on introspection error")
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="server_error"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain error=\"server_error\"", wwwAuth)
	}
}

func TestIntrospectionAuthMiddleware_PropagatesContextValues(t *testing.T) {
	// Arrange
	result := &ports.IntrospectionResult{
		Active:      true,
		Subject:     "user-99",
		ClientID:    "client-99",
		Scope:       "read",
		Permissions: []string{"resources:read"},
	}
	var (
		gotSubject  string
		gotClientID string
		gotScopes   []string
		gotPerms    []string
	)
	captureHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotSubject, _ = r.Context().Value(contextKeySubject).(string)
		gotClientID, _ = r.Context().Value(contextKeyClientID).(string)
		gotScopes, _ = r.Context().Value(contextKeyScopes).([]string)
		gotPerms, _ = r.Context().Value(contextKeyPermissions).([]string)
	})
	mw := IntrospectionAuthMiddleware(&fakeIntrospector{result: result}, testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(captureHandler).ServeHTTP(w, bearerRequest(t, "valid.jwt"))

	// Assert
	if gotSubject != "user-99" {
		t.Errorf("contextKeySubject = %q, want %q", gotSubject, "user-99")
	}
	if gotClientID != "client-99" {
		t.Errorf("contextKeyClientID = %q, want %q", gotClientID, "client-99")
	}
	if len(gotScopes) != 1 || gotScopes[0] != "read" {
		t.Errorf("contextKeyScopes = %v, want [read]", gotScopes)
	}
	if len(gotPerms) != 1 || gotPerms[0] != "resources:read" {
		t.Errorf("contextKeyPermissions = %v, want [resources:read]", gotPerms)
	}
}

// --- JWTAuthMiddleware ---

func TestJWTAuthMiddleware_ValidToken_CallsNext(t *testing.T) {
	// Arrange
	key := []byte("test-signing-key")
	claims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "c1",
		Scope:    "read write",
	}
	raw := signHS256(t, key, claims)
	var called bool
	mw := JWTAuthMiddleware(key, testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d — body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !called {
		t.Error("next handler was not called for a valid JWT")
	}
}

func TestJWTAuthMiddleware_ExpiredToken_Returns401(t *testing.T) {
	// Arrange
	key := []byte("test-signing-key")
	claims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // expired
		},
	}
	raw := signHS256(t, key, claims)
	var called bool
	mw := JWTAuthMiddleware(key, testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called for an expired JWT")
	}
	if wwwAuth := w.Header().Get("WWW-Authenticate"); !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain error=\"invalid_token\"", wwwAuth)
	}
}

func TestJWTAuthMiddleware_WrongSigningKey_Returns401(t *testing.T) {
	// Arrange
	claims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	raw := signHS256(t, []byte("different-key"), claims)
	var called bool
	mw := JWTAuthMiddleware([]byte("actual-key"), testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called for a tampered JWT")
	}
	if wwwAuth := w.Header().Get("WWW-Authenticate"); !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain error=\"invalid_token\"", wwwAuth)
	}
}

func TestJWTAuthMiddleware_MalformedToken_Returns401(t *testing.T) {
	// Arrange
	var called bool
	mw := JWTAuthMiddleware([]byte("key"), testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, "not.a.jwt"))

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if wwwAuth := w.Header().Get("WWW-Authenticate"); !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain error=\"invalid_token\"", wwwAuth)
	}
}

func TestJWTAuthMiddleware_MissingAuthHeader_Returns401(t *testing.T) {
	// Arrange
	var called bool
	mw := JWTAuthMiddleware([]byte("key"), testutil.NewTestLogger())
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestJWTAuthMiddleware_PropagatesContextValues(t *testing.T) {
	// Arrange
	key := []byte("test-signing-key")
	claims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID:    "client-42",
		Scope:       "read",
		Permissions: []string{"resources:read"},
	}
	raw := signHS256(t, key, claims)
	var (
		gotSubject  string
		gotClientID string
		gotScopes   []string
		gotPerms    []string
	)
	captureHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotSubject, _ = r.Context().Value(contextKeySubject).(string)
		gotClientID, _ = r.Context().Value(contextKeyClientID).(string)
		gotScopes, _ = r.Context().Value(contextKeyScopes).([]string)
		gotPerms, _ = r.Context().Value(contextKeyPermissions).([]string)
	})
	mw := JWTAuthMiddleware(key, testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(captureHandler).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if gotSubject != "user-42" {
		t.Errorf("subject = %q, want %q", gotSubject, "user-42")
	}
	if gotClientID != "client-42" {
		t.Errorf("clientID = %q, want %q", gotClientID, "client-42")
	}
	if len(gotScopes) != 1 || gotScopes[0] != "read" {
		t.Errorf("scopes = %v, want [read]", gotScopes)
	}
	if len(gotPerms) != 1 || gotPerms[0] != "resources:read" {
		t.Errorf("permissions = %v, want [resources:read]", gotPerms)
	}
}

// --- RequireScopeMiddleware ---

func TestRequireScopeMiddleware_ScopePresent_CallsNext(t *testing.T) {
	// Arrange
	var called bool
	mw := RequireScopeMiddleware("read")
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r = r.WithContext(context.WithValue(r.Context(), contextKeyScopes, []string{"read", "write"}))
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called when required scope is present")
	}
}

func TestRequireScopeMiddleware_ScopeAbsent_Returns403(t *testing.T) {
	// Arrange
	var called bool
	mw := RequireScopeMiddleware("admin")
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r = r.WithContext(context.WithValue(r.Context(), contextKeyScopes, []string{"read"}))
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if called {
		t.Error("next handler must not be called when required scope is absent")
	}
	// RFC 6750 §3.1: insufficient_scope must include WWW-Authenticate with error="insufficient_scope".
	if wwwAuth := w.Header().Get("WWW-Authenticate"); !strings.Contains(wwwAuth, `error="insufficient_scope"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain error=\"insufficient_scope\"", wwwAuth)
	}
}

func TestRequireScopeMiddleware_NoContextScopes_Returns401(t *testing.T) {
	// Arrange
	// Missing scopes in context means auth middleware did not run — treat as 401.
	var called bool
	mw := RequireScopeMiddleware("read")
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called when scopes are absent from context")
	}
}

func TestRequireScopeMiddleware_EmptyRequiredScope_CallsNext(t *testing.T) {
	// Arrange
	// RequireScopeMiddleware("") matches an empty string scope value in the context.
	// A token whose scope string parses to [""] is unusual but possible (e.g. a scope
	// value that is just spaces). This test documents the current behaviour: the empty
	// string is treated as a valid scope name and "" == "" passes the check.
	var called bool
	mw := RequireScopeMiddleware("")
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r = r.WithContext(context.WithValue(r.Context(), contextKeyScopes, []string{""}))
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called when empty scope matched empty required scope")
	}
}
