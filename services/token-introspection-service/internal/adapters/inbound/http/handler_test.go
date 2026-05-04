//go:build unit

package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/testutil"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/ports"
)

type fakeIntrospector struct {
	result *domain.IntrospectionResult
	err    error
}

func (f *fakeIntrospector) Introspect(_ context.Context, _ string) (*domain.IntrospectionResult, error) {
	return f.result, f.err
}

var _ ports.Introspector = (*fakeIntrospector)(nil)

func postToken(t *testing.T, h *inboundhttp.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Introspect(rr, req)
	return rr
}

func decodeActive(t *testing.T, rr *httptest.ResponseRecorder) bool {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	v, ok := body["active"]
	if !ok {
		t.Fatal("response missing 'active' field")
	}
	active, ok := v.(bool)
	if !ok {
		t.Fatalf("'active' field is not bool: %T", v)
	}
	return active
}

const contentTypeJSON = "application/json"

// TestIntrospect_RFC7662_AlwaysHTTP200 verifies that all introspection responses —
// active, inactive, service error, and missing token — return HTTP 200 per RFC 7662 §2.2.
func TestIntrospect_RFC7662_AlwaysHTTP200(t *testing.T) {
	cases := []struct {
		name         string
		introspector *fakeIntrospector
		token        string
		wantActive   bool
	}{
		{
			name:         "active token",
			introspector: &fakeIntrospector{result: &domain.IntrospectionResult{Active: true, Subject: "user-1"}},
			token:        "valid.token.here",
			wantActive:   true,
		},
		{
			name:         "inactive token",
			introspector: &fakeIntrospector{result: &domain.IntrospectionResult{Active: false}},
			token:        "expired.or.revoked",
			wantActive:   false,
		},
		{
			name:         "service error returns active=false not 5xx",
			introspector: &fakeIntrospector{err: errors.New("redis unavailable")},
			token:        "any.token",
			wantActive:   false,
		},
		{
			// Per RFC 7662 §2.2 and the service invariant in CLAUDE.md:
			// a missing token parameter must return HTTP 200 with {active: false},
			// not a 400 Bad Request — the caller cannot distinguish "bad request"
			// from "invalid token" without knowing the internal representation.
			name:         "missing token returns active=false not 400",
			introspector: &fakeIntrospector{result: &domain.IntrospectionResult{Active: false}},
			token:        "",
			wantActive:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := inboundhttp.NewHandler(tc.introspector, testutil.NewTestLogger(), "")
			rr := postToken(t, h, tc.token)

			if rr.Code != http.StatusOK {
				t.Errorf("HTTP status = %d, want 200 (RFC 7662 §2.2 requires always-200)", rr.Code)
			}
			if ct := rr.Header().Get("Content-Type"); ct != contentTypeJSON {
				t.Errorf("Content-Type = %q, want %q", ct, contentTypeJSON)
			}
			active := decodeActive(t, rr)
			if active != tc.wantActive {
				t.Errorf("active = %v, want %v", active, tc.wantActive)
			}
		})
	}
}

// TestIntrospect_OversizedBody_ReturnsInactive verifies that a request body exceeding
// the 1 MiB limit triggers ParseForm failure, which must still return 200 {active:false}
// per RFC 7662 §2.2 — the caller cannot distinguish a bad request from an invalid token.
func TestIntrospect_OversizedBody_ReturnsInactive(t *testing.T) {
	h := inboundhttp.NewHandler(&fakeIntrospector{result: &domain.IntrospectionResult{Active: false}}, testutil.NewTestLogger(), "")

	// Build a body just over 1 MiB.
	body := strings.Repeat("x", 1<<20+1)
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Introspect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("HTTP status = %d, want 200 (RFC 7662 §2.2 requires always-200)", rr.Code)
	}
	active := decodeActive(t, rr)
	if active {
		t.Error("active = true, want false for oversized body")
	}
}

func TestHealth_Returns200(t *testing.T) {
	h := inboundhttp.NewHandler(&fakeIntrospector{}, testutil.NewTestLogger(), "")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.Health(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestIntrospect_CacheControlNoStore verifies that all introspection responses
// include Cache-Control: no-store and Pragma: no-cache per RFC 7662 §2.4.
func TestIntrospect_CacheControlNoStore(t *testing.T) {
	cases := []struct {
		name         string
		introspector *fakeIntrospector
		token        string
	}{
		{
			name:         "active token",
			introspector: &fakeIntrospector{result: &domain.IntrospectionResult{Active: true}},
			token:        "valid.token",
		},
		{
			name:         "service error",
			introspector: &fakeIntrospector{err: errors.New("store down")},
			token:        "any.token",
		},
		{
			name:         "missing token",
			introspector: &fakeIntrospector{},
			token:        "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			h := inboundhttp.NewHandler(tc.introspector, testutil.NewTestLogger(), "")

			// Act
			rr := postToken(t, h, tc.token)

			// Assert
			if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
			}
			if pragma := rr.Header().Get("Pragma"); pragma != "no-cache" {
				t.Errorf("Pragma = %q, want %q", pragma, "no-cache")
			}
		})
	}
}

// TestIntrospect_WithSecret_Returns401WhenMissing verifies that when a pre-shared secret
// is configured, callers without Authorization: Bearer <secret> receive a 401 per RFC 7662 §2.1.
func TestIntrospect_WithSecret_Returns401WhenMissing(t *testing.T) {
	// Arrange
	h := inboundhttp.NewHandler(&fakeIntrospector{result: &domain.IntrospectionResult{Active: true}}, testutil.NewTestLogger(), "test-secret")

	// Act — no Authorization header
	form := url.Values{"token": {"valid.token"}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Introspect(rr, req)

	// Assert
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("expected JSON error body on 401, got decode error: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error field in JSON body on 401")
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q (RFC 7662 §2.4)", cc, "no-store")
	}
}

// TestIntrospect_RateLimited_Returns429 verifies that per-IP rate limiting is enforced
// on the introspect endpoint (RFC 6819 §4.3.2). After the burst limit is exhausted,
// the handler must return 429 with a Retry-After header (RFC 6585 §4).
func TestIntrospect_RateLimited_Returns429(t *testing.T) {
	// Arrange — use the default handler; all httptest requests share "192.0.2.1:1234"
	h := inboundhttp.NewHandler(
		&fakeIntrospector{result: &domain.IntrospectionResult{Active: true}},
		testutil.NewTestLogger(),
		"",
	)

	// Act — exhaust the per-IP limit (20 requests per minute)
	var lastRR *httptest.ResponseRecorder
	for i := 0; i < 21; i++ {
		lastRR = postToken(t, h, "some.token.value")
	}

	// Assert — 21st request must be rejected with 429
	if lastRR.Code != http.StatusTooManyRequests {
		t.Errorf("status after limit = %d, want %d", lastRR.Code, http.StatusTooManyRequests)
	}
	if ra := lastRR.Header().Get("Retry-After"); ra != "60" {
		t.Errorf("Retry-After = %q, want %q", ra, "60")
	}
}

// TestIntrospect_WithSecret_Returns200WhenCorrect verifies that a valid pre-shared secret
// allows the introspection to proceed normally.
func TestIntrospect_WithSecret_Returns200WhenCorrect(t *testing.T) {
	// Arrange
	h := inboundhttp.NewHandler(&fakeIntrospector{result: &domain.IntrospectionResult{Active: true}}, testutil.NewTestLogger(), "test-secret")

	// Act
	form := url.Values{"token": {"valid.token"}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer test-secret")
	rr := httptest.NewRecorder()
	h.Introspect(rr, req)

	// Assert
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !decodeActive(t, rr) {
		t.Error("active = false, want true")
	}
}
