//go:build unit

package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/jedi-knights/go-platform/jwtutil"

	"github.com/jedi-knights/go-platform/testutil"

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

// signHS256 creates a minimal HS256-signed JWT from cfg.
// ExpiresAt is optional — omitting it produces a non-expiring token, which is
// fine for tests that are not checking expiry behavior.
func signHS256(t *testing.T, key []byte, cfg jwtutil.ClaimsConfig) string {
	t.Helper()
	raw, err := jwtutil.Sign(jwtutil.NewClaims(cfg), key)
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

func TestExtractBearer_InvalidHeaders_Return401(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "missing header", header: ""},
		{name: "wrong scheme", header: "Token xyz"},
		{name: "whitespace-only token", header: "Bearer   "},
		{name: "empty token", header: "Bearer "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			r := httptest.NewRequest(http.MethodGet, "/resources", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()

			// Act
			_, ok := extractBearer(w, r)

			// Assert
			if ok {
				t.Error("extractBearer returned ok=true, want false")
			}
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
			if w.Header().Get("WWW-Authenticate") == "" {
				t.Error("expected WWW-Authenticate header on 401")
			}
		})
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
	mw := IntrospectionAuthMiddleware(&fakeIntrospector{result: result}, testutil.NewTestLogger(), "")
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
	mw := IntrospectionAuthMiddleware(&fakeIntrospector{result: result}, testutil.NewTestLogger(), "")
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
	mw := IntrospectionAuthMiddleware(introspector, testutil.NewTestLogger(), "")
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
	mw := IntrospectionAuthMiddleware(&fakeIntrospector{result: result}, testutil.NewTestLogger(), "")
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

// TestIntrospectionAuthMiddleware_PropagatesCNFJKT covers RFC 9449
// (ADR-0025 in identity-platform-go's auth-server): the introspection
// result's DPoP confirmation thumbprint must reach context so
// RequireDPoPMiddleware can enforce proof-of-possession downstream.
func TestIntrospectionAuthMiddleware_PropagatesCNFJKT(t *testing.T) {
	// Arrange
	result := &ports.IntrospectionResult{Active: true, Subject: "user-1", CNFJKT: "test-jkt-value"}
	var gotJKT string
	captureHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotJKT, _ = r.Context().Value(contextKeyCNFJKT).(string)
	})
	mw := IntrospectionAuthMiddleware(&fakeIntrospector{result: result}, testutil.NewTestLogger(), "")
	w := httptest.NewRecorder()

	// Act
	mw(captureHandler).ServeHTTP(w, bearerRequest(t, "valid.jwt"))

	// Assert
	if gotJKT != "test-jkt-value" {
		t.Errorf("contextKeyCNFJKT = %q, want %q", gotJKT, "test-jkt-value")
	}
}

// --- JWTAuthMiddleware ---

func TestJWTAuthMiddleware_ValidToken_CallsNext(t *testing.T) {
	// Arrange
	key := []byte("test-signing-key")
	raw := signHS256(t, key, jwtutil.ClaimsConfig{
		Subject:   "user-1",
		ExpiresAt: time.Now().Add(time.Hour),
		ClientID:  "c1",
		Scope:     "read write",
	})
	var called bool
	mw := JWTAuthMiddleware(key, "", "", testutil.NewTestLogger())
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
	raw := signHS256(t, key, jwtutil.ClaimsConfig{
		Subject:   "user-1",
		ExpiresAt: time.Now().Add(-time.Hour), // expired
	})
	var called bool
	mw := JWTAuthMiddleware(key, "", "", testutil.NewTestLogger())
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
	raw := signHS256(t, []byte("different-key"), jwtutil.ClaimsConfig{
		Subject:   "user-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	var called bool
	mw := JWTAuthMiddleware([]byte("actual-key"), "", "", testutil.NewTestLogger())
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
	mw := JWTAuthMiddleware([]byte("key"), "", "", testutil.NewTestLogger())
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
	mw := JWTAuthMiddleware([]byte("key"), "", "", testutil.NewTestLogger())
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
	raw := signHS256(t, key, jwtutil.ClaimsConfig{
		Subject:     "user-42",
		ExpiresAt:   time.Now().Add(time.Hour),
		ClientID:    "client-42",
		Scope:       "read",
		Permissions: []string{"resources:read"},
	})
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
	mw := JWTAuthMiddleware(key, "", "", testutil.NewTestLogger())
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

func TestRequireScopeMiddleware_EmptyRequiredScope_Panics(t *testing.T) {
	// Arrange / Act / Assert
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected RequireScopeMiddleware(\"\") to panic, got nil")
		}
	}()
	RequireScopeMiddleware("")
}

func TestRequireScopeMiddleware_ScopeAbsent_IncludesScopeInWWWAuthenticate(t *testing.T) {
	// RFC 6750 §3.1: insufficient_scope WWW-Authenticate must include the required scope.

	// Arrange
	var called bool
	mw := RequireScopeMiddleware("read")
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r = r.WithContext(context.WithValue(r.Context(), contextKeyScopes, []string{"write"}))
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `scope="read"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain scope=\"read\"", wwwAuth)
	}
}

// --- RequireACRMiddleware (RFC 9470, ADR-0024 in identity-platform-go's auth-server) ---

func TestRequireACRMiddleware_ACRMatches_CallsNext(t *testing.T) {
	// Arrange
	var called bool
	mw := RequireACRMiddleware("pwd")
	r := httptest.NewRequest(http.MethodGet, "/resources/sensitive", nil)
	r = r.WithContext(context.WithValue(r.Context(), contextKeyAcr, "pwd"))
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !called {
		t.Error("next handler was not called when required acr is present")
	}
}

func TestRequireACRMiddleware_ACRAbsent_Returns401WithChallenge(t *testing.T) {
	// RFC 9470 §5: a token whose authentication context is insufficient
	// gets a 401 (not 403 — unlike scope, this is about authentication
	// strength, not authorization) with error="insufficient_user_authentication"
	// and the acr_values that would satisfy it.

	// Arrange
	var called bool
	mw := RequireACRMiddleware("pwd")
	r := httptest.NewRequest(http.MethodGet, "/resources/sensitive", nil)
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called when acr is absent")
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="insufficient_user_authentication"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain error=\"insufficient_user_authentication\"", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `acr_values="pwd"`) {
		t.Errorf("WWW-Authenticate = %q, want it to contain acr_values=\"pwd\"", wwwAuth)
	}
}

func TestRequireACRMiddleware_ACRMismatch_Returns401WithChallenge(t *testing.T) {
	// Arrange
	var called bool
	mw := RequireACRMiddleware("pwd")
	r := httptest.NewRequest(http.MethodGet, "/resources/sensitive", nil)
	r = r.WithContext(context.WithValue(r.Context(), contextKeyAcr, "urn:example:some-other-method"))
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called when acr does not match")
	}
}

func TestRequireACRMiddleware_EmptyRequiredACR_Panics(t *testing.T) {
	// Arrange / Act / Assert
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected RequireACRMiddleware(\"\") to panic, got nil")
		}
	}()
	RequireACRMiddleware("")
}

func TestIntrospectionAuthMiddleware_PropagatesAcr(t *testing.T) {
	// ADR-0024: the introspection result's Acr must reach contextKeyAcr so
	// RequireACRMiddleware can read it.

	// Arrange
	var gotAcr string
	introspector := &fakeIntrospector{result: &ports.IntrospectionResult{Active: true, Subject: "user-1", Acr: "pwd"}}
	mw := IntrospectionAuthMiddleware(introspector, testutil.NewTestLogger(), "")
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAcr, _ = r.Context().Value(contextKeyAcr).(string)
	})
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	r.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()

	// Act
	mw(next).ServeHTTP(w, r)

	// Assert
	if gotAcr != "pwd" {
		t.Errorf("contextKeyAcr = %q, want %q", gotAcr, "pwd")
	}
}

func TestJWTAuthMiddleware_WithAudience_ValidAudience_CallsNext(t *testing.T) {
	// Arrange
	key := []byte("test-signing-key")
	raw := signHS256(t, key, jwtutil.ClaimsConfig{
		Subject:   "user-1",
		ExpiresAt: time.Now().Add(time.Hour),
		Audience:  []string{"my-resource-service"},
	})
	var called bool
	mw := JWTAuthMiddleware(key, "my-resource-service", "", testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d — body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !called {
		t.Error("next handler was not called for a token with matching audience")
	}
}

func TestJWTAuthMiddleware_WithAudience_WrongAudience_Returns401(t *testing.T) {
	// RFC 9700 §2.3: tokens must be validated against the expected audience.

	// Arrange
	key := []byte("test-signing-key")
	raw := signHS256(t, key, jwtutil.ClaimsConfig{
		Subject:   "user-1",
		ExpiresAt: time.Now().Add(time.Hour),
		Audience:  []string{"other-service"},
	})
	var called bool
	mw := JWTAuthMiddleware(key, "my-resource-service", "", testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, bearerRequest(t, raw))

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called for a token with wrong audience")
	}
}

// --- RequireDPoPMiddleware (RFC 9449, ADR-0025 in identity-platform-go's auth-server) ---

// buildDPoPProof signs a fresh ES256 DPoP proof for htm/htu, mirroring
// exactly what a real client presents to a resource server per RFC 9449
// §4.2/§4.3. Deliberately duplicated from auth-server's own test helper
// (dpop_validator_test.go) rather than shared — see ADR-0025's "a little
// copying is better than a little dependency" rationale for why this
// service's DPoP proof verification has its own small implementation
// rather than importing auth-server's.
func buildDPoPProof(t *testing.T, htm, htu string) (string, string) {
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
	jwkHeader := map[string]any{"kty": "EC", "crv": "P-256", "x": enc(point[1 : 1+coordSize]), "y": enc(point[1+coordSize:])}
	claims := jwt.MapClaims{"htm": htm, "htu": htu, "iat": time.Now().Unix(), "jti": "jti-" + t.Name()}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkHeader
	proof, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing proof: %v", err)
	}
	jkt, err := jwkThumbprint(jwkHeader)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}
	return proof, jkt
}

// requestWithCNFJKT builds a GET /resources request carrying jkt on
// contextKeyCNFJKT, as IntrospectionAuthMiddleware would have set it.
func requestWithCNFJKT(jkt string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/resources", nil)
	ctx := context.WithValue(r.Context(), contextKeyCNFJKT, jkt)
	return r.WithContext(ctx)
}

func TestRequireDPoPMiddleware_NoConfirmedJKT_CallsNextUnconditionally(t *testing.T) {
	// Arrange — ordinary bearer token (empty jkt); no DPoP header sent either.
	var called bool
	mw := RequireDPoPMiddleware(testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, requestWithCNFJKT(""))

	// Assert
	if !called {
		t.Error("expected next handler to be called for a non-DPoP-bound token")
	}
}

func TestRequireDPoPMiddleware_ConfirmedJKT_ValidMatchingProof_CallsNext(t *testing.T) {
	// Arrange
	proof, jkt := buildDPoPProof(t, http.MethodGet, "http://example.com/resources")
	var called bool
	mw := RequireDPoPMiddleware(testutil.NewTestLogger())
	w := httptest.NewRecorder()
	r := requestWithCNFJKT(jkt)
	r.Header.Set("DPoP", proof)

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if !called {
		t.Errorf("expected next handler to be called; status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestRequireDPoPMiddleware_ConfirmedJKT_MissingProof_Returns401(t *testing.T) {
	// Arrange
	var called bool
	mw := RequireDPoPMiddleware(testutil.NewTestLogger())
	w := httptest.NewRecorder()

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, requestWithCNFJKT("some-jkt"))

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called when a DPoP-bound token has no proof")
	}
}

func TestRequireDPoPMiddleware_ConfirmedJKT_ProofKeyMismatch_Returns401(t *testing.T) {
	// Arrange — proof is valid but signed by a different key than the token confirms.
	proof, _ := buildDPoPProof(t, http.MethodGet, "http://example.com/resources")
	var called bool
	mw := RequireDPoPMiddleware(testutil.NewTestLogger())
	w := httptest.NewRecorder()
	r := requestWithCNFJKT("a-completely-different-jkt")
	r.Header.Set("DPoP", proof)

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called when the proof key does not match cnf.jkt")
	}
}

func TestRequireDPoPMiddleware_ConfirmedJKT_HTUMismatch_Returns401(t *testing.T) {
	// Arrange — proof is for a different resource path.
	proof, jkt := buildDPoPProof(t, http.MethodGet, "http://example.com/other-path")
	var called bool
	mw := RequireDPoPMiddleware(testutil.NewTestLogger())
	w := httptest.NewRecorder()
	r := requestWithCNFJKT(jkt)
	r.Header.Set("DPoP", proof)

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called when htu does not match the request")
	}
}

func TestRequireDPoPMiddleware_ConfirmedJKT_MalformedProof_Returns401(t *testing.T) {
	// Arrange
	var called bool
	mw := RequireDPoPMiddleware(testutil.NewTestLogger())
	w := httptest.NewRecorder()
	r := requestWithCNFJKT("some-jkt")
	r.Header.Set("DPoP", "not-a-jwt")

	// Act
	mw(okHandler(t, &called)).ServeHTTP(w, r)

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler must not be called for a malformed proof")
	}
}
