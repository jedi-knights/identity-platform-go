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
			h := inboundhttp.NewHandler(tc.introspector, testutil.NewTestLogger())
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
	h := inboundhttp.NewHandler(&fakeIntrospector{result: &domain.IntrospectionResult{Active: false}}, testutil.NewTestLogger())

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
	h := inboundhttp.NewHandler(&fakeIntrospector{}, testutil.NewTestLogger())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.Health(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}
