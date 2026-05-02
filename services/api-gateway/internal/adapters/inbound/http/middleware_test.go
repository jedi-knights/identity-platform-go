//go:build unit

package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	gatewayhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/auth/hs256"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
)

// testSigningKey is the HMAC-SHA256 key used to sign tokens in all middleware tests.
var testSigningKey = []byte("test-signing-key-that-is-32chars!!")

// signToken creates a valid signed JWT for use in tests.
func signToken(t *testing.T, subject, scope string, roles []string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "identity-platform",
		Subject:   subject,
		TokenID:   "test-id",
		ClientID:  subject,
		Scope:     scope,
		Roles:     roles,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	})
	token, err := jwtutil.Sign(claims, testSigningKey)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}
	return token
}

// --- Token validation ---

// TestJWTMiddleware_ValidToken_Passes confirms that a well-formed, unexpired
// token with valid signature passes through and reaches the downstream handler.
func TestJWTMiddleware_ValidToken_Passes(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	reached := false
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), nil, logger)(downstream)
	token := signToken(t, "user-1", "read write", nil, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
	if !reached {
		t.Error("downstream handler was not reached for a valid token")
	}
}

// TestJWTMiddleware_MissingToken_Returns401 confirms that requests without
// an Authorization header are rejected before reaching the downstream handler.
func TestJWTMiddleware_MissingToken_Returns401(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), nil, logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestJWTMiddleware_ExpiredToken_Returns401 verifies that expired tokens are
// rejected even if the signature is valid.
func TestJWTMiddleware_ExpiredToken_Returns401(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), nil, logger)(downstream)
	token := signToken(t, "user-1", "read", nil, -time.Hour) // expired an hour ago
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestJWTMiddleware_WrongKey_Returns401 confirms that tokens signed with a
// different key are rejected (guards against algorithm confusion attacks).
func TestJWTMiddleware_WrongKey_Returns401(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), nil, logger)(downstream)
	wrongKey := []byte("wrong-key-that-is-also-32-chars!!")
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Subject:   "attacker",
		TokenID:   "x",
		ClientID:  "x",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	token, err := jwtutil.Sign(claims, wrongKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestJWTMiddleware_MalformedToken_Returns401 checks that a non-JWT string in
// the Authorization header is rejected.
func TestJWTMiddleware_MalformedToken_Returns401(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), nil, logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt")
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// --- Header injection (forward-auth pattern) ---

// TestJWTMiddleware_InjectsAuthHeaders verifies the forward-auth pattern:
// verified identity claims are injected as X-Auth-* headers so that
// upstream services can trust them without validating JWT themselves.
func TestJWTMiddleware_InjectsAuthHeaders(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	var got http.Header
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), nil, logger)(downstream)
	token := signToken(t, "user-42", "read write", []string{"admin", "editor"}, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// Act
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	if got.Get("X-Auth-Subject") != "user-42" {
		t.Errorf("X-Auth-Subject = %q, want %q", got.Get("X-Auth-Subject"), "user-42")
	}
	if got.Get("X-Auth-Scope") != "read write" {
		t.Errorf("X-Auth-Scope = %q, want %q", got.Get("X-Auth-Scope"), "read write")
	}
	if got.Get("X-Auth-Roles") != "admin,editor" {
		t.Errorf("X-Auth-Roles = %q, want %q", got.Get("X-Auth-Roles"), "admin,editor")
	}
}

// --- Header spoofing prevention ---

// TestJWTMiddleware_StripsClientAuthHeaders verifies that a client cannot
// spoof upstream identity by pre-setting X-Auth-* headers before the gateway.
// These headers must be stripped unconditionally — even on valid requests —
// because the middleware's injected values are the only trusted source.
func TestJWTMiddleware_StripsClientAuthHeaders(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	var got http.Header
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), nil, logger)(downstream)
	token := signToken(t, "real-user", "read", nil, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Client attempts to escalate privileges by pre-injecting auth headers.
	req.Header.Set("X-Auth-Subject", "admin")
	req.Header.Set("X-Auth-Scope", "admin:write")
	req.Header.Set("X-Auth-Roles", "superadmin")

	// Act
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// Assert — must reflect the token claims, not the client-provided values.
	if got.Get("X-Auth-Subject") != "real-user" {
		t.Errorf("X-Auth-Subject = %q, want %q (client spoof not stripped)", got.Get("X-Auth-Subject"), "real-user")
	}
	if got.Get("X-Auth-Roles") != "" {
		t.Errorf("X-Auth-Roles = %q, want empty (token had no roles)", got.Get("X-Auth-Roles"))
	}
}

// TestJWTMiddleware_StripsAuthHeadersOnPublicPath verifies that even on public
// (unauthenticated) paths, client-injected X-Auth-* headers are stripped so
// upstreams cannot be deceived on endpoints that bypass JWT validation.
func TestJWTMiddleware_StripsAuthHeadersOnPublicPath(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	var got http.Header
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), []string{"/public"}, logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/public/resource", nil)
	req.Header.Set("X-Auth-Subject", "hacker") // no Authorization header — public path
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusOK {
		t.Errorf("public path got status %d, want %d", rr.Code, http.StatusOK)
	}
	if got.Get("X-Auth-Subject") != "" {
		t.Errorf("X-Auth-Subject = %q on public path; should be stripped", got.Get("X-Auth-Subject"))
	}
}

// --- Public path bypass ---

// TestJWTMiddleware_PublicPath_NoToken_Passes verifies that requests to
// configured public paths reach the downstream without a token.
func TestJWTMiddleware_PublicPath_NoToken_Passes(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	reached := false
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), []string{"/public", "/open"}, logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/public/signup", nil)
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
	if !reached {
		t.Error("downstream was not reached for a public path")
	}
}

// TestJWTMiddleware_NonPublicPath_NoToken_Returns401 confirms that a path that
// does not match any public prefix still requires a token.
func TestJWTMiddleware_NonPublicPath_NoToken_Returns401(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := gatewayhttp.JWTMiddleware(hs256.NewVerifier(testSigningKey), []string{"/public"}, logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	rr := httptest.NewRecorder()

	// Act
	handler.ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// --- RequestIDMiddleware ---

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestRequestIDMiddleware_GeneratesIDWhenAbsent verifies that a request without
// an X-Request-ID header receives a freshly generated UUID v4.
func TestRequestIDMiddleware_GeneratesIDWhenAbsent(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := gatewayhttp.RequestIDMiddleware(logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	rr := httptest.NewRecorder()

	// Act
	mw.ServeHTTP(rr, req)

	// Assert
	got := rr.Header().Get("X-Request-ID")
	if got == "" {
		t.Fatal("X-Request-ID response header not set")
	}
	if !uuidV4.MatchString(got) {
		t.Errorf("X-Request-ID = %q is not a valid UUID v4", got)
	}
}

// TestRequestIDMiddleware_AcceptsValidClientUUID verifies that a request carrying
// a valid UUID v4 as X-Request-ID has that exact value echoed back, not replaced.
func TestRequestIDMiddleware_AcceptsValidClientUUID(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	clientID := "550e8400-e29b-41d4-a716-446655440000"
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := gatewayhttp.RequestIDMiddleware(logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-Request-ID", clientID)
	rr := httptest.NewRecorder()

	// Act
	mw.ServeHTTP(rr, req)

	// Assert
	if got := rr.Header().Get("X-Request-ID"); got != clientID {
		t.Errorf("X-Request-ID = %q, want %q (client UUID not preserved)", got, clientID)
	}
}

// TestRequestIDMiddleware_ReplacesInvalidClientID verifies that a crafted or
// non-UUID X-Request-ID is replaced with a generated UUID to prevent log injection.
func TestRequestIDMiddleware_ReplacesInvalidClientID(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := gatewayhttp.RequestIDMiddleware(logger)(downstream)
	malicious := "../../../../etc/passwd"
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-Request-ID", malicious)
	rr := httptest.NewRecorder()

	// Act
	mw.ServeHTTP(rr, req)

	// Assert
	got := rr.Header().Get("X-Request-ID")
	if got == malicious {
		t.Error("malicious X-Request-ID was not replaced")
	}
	if got == "" {
		t.Error("X-Request-ID response header not set after replacement")
	}
	if !uuidV4.MatchString(got) {
		t.Errorf("replacement X-Request-ID = %q is not a valid UUID v4", got)
	}
}

// TestRequestIDMiddleware_PropagatesIDToRequestHeader verifies that the final
// request ID (generated or accepted) is set on the outbound request header so
// that upstream services receive it for correlation.
func TestRequestIDMiddleware_PropagatesIDToRequestHeader(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	clientID := "550e8400-e29b-41d4-a716-446655440000"
	var gotRequestHeader string
	downstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRequestHeader = r.Header.Get("X-Request-ID")
	})
	mw := gatewayhttp.RequestIDMiddleware(logger)(downstream)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-Request-ID", clientID)

	// Act
	mw.ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	if gotRequestHeader != clientID {
		t.Errorf("upstream got X-Request-ID = %q, want %q", gotRequestHeader, clientID)
	}
}

// --- RateLimitMiddleware key source tests ---

func TestRateLimitMiddleware_KeySource_XForwardedFor(t *testing.T) {
	// Arrange
	var capturedKey string
	limiter := &capturingLimiter{captureFunc: func(key string) { capturedKey = key }}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.RateLimitMiddleware(limiter, "x-forwarded-for", logger)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.2")

	// Act
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	if capturedKey != "203.0.113.1" {
		t.Errorf("key = %q, want %q", capturedKey, "203.0.113.1")
	}
}

func TestRateLimitMiddleware_KeySource_JWTSubject(t *testing.T) {
	// Arrange
	var capturedKey string
	limiter := &capturingLimiter{captureFunc: func(key string) { capturedKey = key }}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.RateLimitMiddleware(limiter, "jwt-subject", logger)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Auth-Subject", "user-abc-123")

	// Act
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	if capturedKey != "user-abc-123" {
		t.Errorf("key = %q, want %q", capturedKey, "user-abc-123")
	}
}

func TestRateLimitMiddleware_KeySource_FallsBackToIPWhenHeaderMissing(t *testing.T) {
	// Arrange
	var capturedKey string
	limiter := &capturingLimiter{captureFunc: func(key string) { capturedKey = key }}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.RateLimitMiddleware(limiter, "x-real-ip", logger)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "192.168.1.50:9000"
	// X-Real-IP not set — should fall back to RemoteAddr IP

	// Act
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	if capturedKey != "192.168.1.50" {
		t.Errorf("key = %q, want fallback IP %q", capturedKey, "192.168.1.50")
	}
}

// capturingLimiter records the key passed to Allow and always permits.
type capturingLimiter struct {
	captureFunc func(string)
}

func (c *capturingLimiter) Allow(key string) bool {
	if c.captureFunc != nil {
		c.captureFunc(key)
	}
	return true
}

// --- IPFilterMiddleware tests ---

func TestIPFilterMiddleware_DenyMode_BlocksMatchingCIDR(t *testing.T) {
	// Arrange
	cfg := config.IPFilterConfig{
		Enabled:   true,
		Mode:      "deny",
		CIDRs:     []string{"10.0.0.0/8"},
		KeySource: "ip",
	}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.IPFilterMiddleware(cfg, logger)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.5.6.7:1234"
	rr := httptest.NewRecorder()

	// Act
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestIPFilterMiddleware_DenyMode_AllowsNonMatchingIP(t *testing.T) {
	// Arrange
	cfg := config.IPFilterConfig{
		Enabled:   true,
		Mode:      "deny",
		CIDRs:     []string{"10.0.0.0/8"},
		KeySource: "ip",
	}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.IPFilterMiddleware(cfg, logger)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "203.0.113.5:4321"
	rr := httptest.NewRecorder()
	passed := false

	// Act
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passed = true })).ServeHTTP(rr, req)

	// Assert
	if !passed {
		t.Error("expected request to pass through deny-mode filter for non-matching IP")
	}
}

func TestIPFilterMiddleware_AllowMode_BlocksNonMatchingIP(t *testing.T) {
	// Arrange
	cfg := config.IPFilterConfig{
		Enabled:   true,
		Mode:      "allow",
		CIDRs:     []string{"192.168.0.0/16"},
		KeySource: "ip",
	}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.IPFilterMiddleware(cfg, logger)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rr := httptest.NewRecorder()

	// Act
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestIPFilterMiddleware_AllowMode_PermitsMatchingIP(t *testing.T) {
	// Arrange
	cfg := config.IPFilterConfig{
		Enabled:   true,
		Mode:      "allow",
		CIDRs:     []string{"192.168.0.0/16"},
		KeySource: "ip",
	}
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.IPFilterMiddleware(cfg, logger)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "192.168.1.100:5678"
	rr := httptest.NewRecorder()
	passed := false

	// Act
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passed = true })).ServeHTTP(rr, req)

	// Assert
	if !passed {
		t.Error("expected request to pass through allow-mode filter for matching IP")
	}
}

// --- CompressionMiddleware tests ---

func TestCompressionMiddleware_CompressesLargeJSONResponse(t *testing.T) {
	// Arrange
	cfg := config.CompressionConfig{Enabled: true, MinSizeBytes: 10, Level: 6}
	body := strings.Repeat(`{"key":"value"}`, 20) // well above 10 bytes
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mw := gatewayhttp.CompressionMiddleware(cfg, logging.NewLogger(logging.Config{Output: io.Discard}))(upstream)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()

	// Act
	mw.ServeHTTP(rr, req)

	// Assert
	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", rr.Header().Get("Content-Encoding"))
	}
}

func TestCompressionMiddleware_SkipsClientWithoutGzip(t *testing.T) {
	// Arrange
	cfg := config.CompressionConfig{Enabled: true, MinSizeBytes: 1, Level: 6}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"k":"v"}`))
	})
	mw := gatewayhttp.CompressionMiddleware(cfg, logging.NewLogger(logging.Config{Output: io.Discard}))(upstream)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	// Accept-Encoding deliberately not set
	rr := httptest.NewRecorder()

	// Act
	mw.ServeHTTP(rr, req)

	// Assert
	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Error("expected no gzip compression when client did not send Accept-Encoding: gzip")
	}
}

func TestCompressionMiddleware_SkipsSmallResponse(t *testing.T) {
	// Arrange
	cfg := config.CompressionConfig{Enabled: true, MinSizeBytes: 10000, Level: 6}
	body := `{"k":"v"}` // much smaller than threshold
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mw := gatewayhttp.CompressionMiddleware(cfg, logging.NewLogger(logging.Config{Output: io.Discard}))(upstream)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()

	// Act
	mw.ServeHTTP(rr, req)

	// Assert
	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Error("expected no compression for response smaller than min_size_bytes")
	}
}

func TestCompressionMiddleware_DoesNotDoubleCompress(t *testing.T) {
	// Arrange
	cfg := config.CompressionConfig{Enabled: true, MinSizeBytes: 1, Level: 6}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Upstream already compressed the response.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte(`already-compressed`))
	})
	mw := gatewayhttp.CompressionMiddleware(cfg, logging.NewLogger(logging.Config{Output: io.Discard}))(upstream)
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()

	// Act
	mw.ServeHTTP(rr, req)

	// Assert — upstream body must pass through unchanged
	if rr.Body.String() != "already-compressed" {
		t.Errorf("body = %q, expected upstream value to pass through unchanged", rr.Body.String())
	}
}

// --- RateLimitMiddleware rejection tests ---

func TestRateLimitMiddleware_ExceedLimit_Returns429(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.RateLimitMiddleware(&rejectingRateLimiter{}, "ip", logger)

	// Act
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

func TestRateLimitMiddleware_ExceedLimit_SetsRetryAfterHeader(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.RateLimitMiddleware(&rejectingRateLimiter{}, "ip", logger)

	// Act
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header must be set on rate limit rejection")
	}
}

// rejectingRateLimiter always denies.
type rejectingRateLimiter struct{}

func (rejectingRateLimiter) Allow(string) bool { return false }

// --- ConcurrencyMiddleware tests ---

func TestConcurrencyMiddleware_ExceedLimit_Returns503(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.ConcurrencyMiddleware(&rejectingConcurrencyLimiter{}, "ip", logger)

	// Act
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestConcurrencyMiddleware_ExceedLimit_SetsRetryAfterHeader(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	mw := gatewayhttp.ConcurrencyMiddleware(&rejectingConcurrencyLimiter{}, "ip", logger)

	// Act
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header must be set on concurrency limit rejection")
	}
}

func TestConcurrencyMiddleware_SlotReleasedAfterHandler(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	tr := &trackingConcurrencyLimiter{}
	mw := gatewayhttp.ConcurrencyMiddleware(tr, "ip", logger)

	// Act
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert
	if tr.acquireCalls != 1 {
		t.Errorf("Acquire calls = %d, want 1", tr.acquireCalls)
	}
	if tr.releaseCalls != 1 {
		t.Errorf("Release calls = %d, want 1 (slot must be released after handler returns)", tr.releaseCalls)
	}
}

func TestConcurrencyMiddleware_SlotNotReleasedOnDeny(t *testing.T) {
	// Arrange
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	lim := &rejectingConcurrencyLimiter{}
	mw := gatewayhttp.ConcurrencyMiddleware(lim, "ip", logger)

	// Act
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	// Assert — deny path must not call Release (no slot was acquired)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if lim.releaseCalled {
		t.Error("Release must not be called when Acquire returned false")
	}
}

// rejectingConcurrencyLimiter always denies Acquire; Release must never be called on it.
type rejectingConcurrencyLimiter struct{ releaseCalled bool }

func (c *rejectingConcurrencyLimiter) Acquire(string) bool { return false }
func (c *rejectingConcurrencyLimiter) Release(string)      { c.releaseCalled = true }

// trackingConcurrencyLimiter always permits and counts Acquire/Release calls.
type trackingConcurrencyLimiter struct {
	acquireCalls int
	releaseCalls int
}

func (t *trackingConcurrencyLimiter) Acquire(string) bool { t.acquireCalls++; return true }
func (t *trackingConcurrencyLimiter) Release(string)      { t.releaseCalls++ }
