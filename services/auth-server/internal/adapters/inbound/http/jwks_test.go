package http_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// jwksResponse mirrors the wire shape of RFC 7517 §5.
type jwksResponse struct {
	Keys []map[string]string `json:"keys"`
}

func newSingleKeySet(t *testing.T, kid string) *domain.KeySet {
	t.Helper()
	current, err := domain.GenerateSigningKey(kid)
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	ks, err := domain.NewKeySet(current, nil, nil)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return ks
}

// assertJWKFields fails the test for every mismatched field. Field names are
// looked up directly in the map so a missing field is reported the same way
// as a wrong value.
func assertJWKFields(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// assertJWKNonEmpty fails the test if any of the named fields is the empty string.
func assertJWKNonEmpty(t *testing.T, got map[string]string, fields ...string) {
	t.Helper()
	for _, f := range fields {
		if got[f] == "" {
			t.Errorf("%s is empty", f)
		}
	}
}

func TestJWKSHandler_ReturnsOKWithCurrentKey(t *testing.T) {
	// Arrange
	ks := newSingleKeySet(t, "kid-jwks-1")
	h := authhttp.NewJWKSHandler(ks)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	// Act
	h.Get(w, r)

	// Assert
	if got := w.Code; got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	var body jwksResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(body.Keys))
	}
	got := body.Keys[0]
	assertJWKFields(t, got, map[string]string{
		"kid": "kid-jwks-1",
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
	})
	assertJWKNonEmpty(t, got, "n", "e")
}

func TestJWKSHandler_EmitsAllSlotsInOrder(t *testing.T) {
	// Arrange
	current, _ := domain.GenerateSigningKey("kid-current")
	retiring, _ := domain.GenerateSigningKey("kid-retiring")
	next, _ := domain.GenerateSigningKey("kid-next")
	ks, _ := domain.NewKeySet(current, retiring, next)
	h := authhttp.NewJWKSHandler(ks)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	// Act
	h.Get(w, r)

	// Assert
	var body jwksResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(body.Keys))
	}
	wantOrder := []string{"kid-current", "kid-retiring", "kid-next"}
	for i, want := range wantOrder {
		if body.Keys[i]["kid"] != want {
			t.Errorf("keys[%d].kid = %q, want %q", i, body.Keys[i]["kid"], want)
		}
	}
}

func TestJWKSHandler_SetsCacheControlHeader(t *testing.T) {
	// Arrange
	ks := newSingleKeySet(t, "kid-cache")
	h := authhttp.NewJWKSHandler(ks)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	// Act
	h.Get(w, r)

	// Assert
	cc := w.Header().Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=3600")
	}
}

func TestJWKSHandler_SetsContentType(t *testing.T) {
	// Arrange — RFC 7517 §8.5 prefers application/jwk-set+json, but
	// application/json is broadly accepted by clients and intermediaries.
	ks := newSingleKeySet(t, "kid-ct")
	h := authhttp.NewJWKSHandler(ks)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	// Act
	h.Get(w, r)

	// Assert
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q, want a JSON variant", ct)
	}
}

func TestJWKSHandler_DoesNotExposePrivateKey(t *testing.T) {
	// Arrange — the response must never carry the private modulus components
	// ("d", "p", "q", "dp", "dq", "qi" per RFC 7518 §6.3.2). A bare grep for
	// '"d":' in the body is enough for this hazard.
	ks := newSingleKeySet(t, "kid-leak-check")
	h := authhttp.NewJWKSHandler(ks)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	// Act
	h.Get(w, r)

	// Assert
	body := w.Body.String()
	for _, field := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`, "PRIVATE"} {
		if strings.Contains(body, field) {
			t.Errorf("JWKS response leaks private key field %q; body = %s", field, body)
		}
	}
}

func TestJWKSHandler_NEncodingIsBase64URLWithoutPadding(t *testing.T) {
	// Arrange
	ks := newSingleKeySet(t, "kid-encoding")
	h := authhttp.NewJWKSHandler(ks)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	// Act
	h.Get(w, r)

	// Assert
	var body jwksResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	n := body.Keys[0]["n"]
	if strings.Contains(n, "=") {
		t.Errorf("'n' = %q contains padding; RFC 7517 §3 requires unpadded base64url", n)
	}
	if _, err := base64.RawURLEncoding.DecodeString(n); err != nil {
		t.Errorf("'n' = %q is not valid unpadded base64url: %v", n, err)
	}
}

func TestNewJWKSHandler_NilKeySet(t *testing.T) {
	// Arrange / Act / Assert — nil keyset is a programmer error, surfaced at
	// construction time rather than as a nil-deref inside the handler.
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected NewJWKSHandler(nil) to panic, got nil")
		}
	}()
	_ = authhttp.NewJWKSHandler(nil)
}
