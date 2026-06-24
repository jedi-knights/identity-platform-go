//go:build unit

package domain_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// generatePEMKey returns a freshly generated RSA private key encoded as
// PKCS#8 PEM — the format Load* should accept.
func generatePEMKey(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return string(encoded), priv
}

func TestLoadSigningKey_ValidPEM(t *testing.T) {
	pemStr, _ := generatePEMKey(t)

	key, err := domain.LoadSigningKey(pemStr, "test-kid-1")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if key.KID != "test-kid-1" {
		t.Errorf("KID = %q, want %q", key.KID, "test-kid-1")
	}
	if key.Private == nil {
		t.Error("Private = nil, want non-nil")
	}
	if key.Public == nil {
		t.Error("Public = nil, want non-nil")
	}
	// Public must be derived from Private.
	if !key.Private.PublicKey.Equal(key.Public) {
		t.Error("Public is not derived from Private")
	}
}

func TestLoadSigningKey_EmptyPEM(t *testing.T) {
	_, err := domain.LoadSigningKey("", "test-kid")
	if err == nil {
		t.Fatal("expected error for empty PEM, got nil")
	}
}

func TestLoadSigningKey_MalformedPEM(t *testing.T) {
	_, err := domain.LoadSigningKey("not a pem block", "test-kid")
	if err == nil {
		t.Fatal("expected error for malformed PEM, got nil")
	}
}

func TestLoadSigningKey_EmptyKID(t *testing.T) {
	pemStr, _ := generatePEMKey(t)
	_, err := domain.LoadSigningKey(pemStr, "")
	if err == nil {
		t.Fatal("expected error for empty kid, got nil")
	}
}

func TestLoadSigningKey_TooSmallKey(t *testing.T) {
	// 1024-bit key is below the 2048-bit floor per RFC 7518 §3.3.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	_, err = domain.LoadSigningKey(pemStr, "small-key")
	if err == nil {
		t.Fatal("expected error for sub-2048-bit key, got nil")
	}
}

func TestGenerateSigningKey_FreshKey(t *testing.T) {
	key, err := domain.GenerateSigningKey("gen-kid-1")
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	if key.KID != "gen-kid-1" {
		t.Errorf("KID = %q, want %q", key.KID, "gen-kid-1")
	}
	if key.Private == nil {
		t.Error("Private = nil")
	}
	if key.Private.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", key.Private.N.BitLen())
	}
}

func TestGenerateSigningKey_EmptyKID(t *testing.T) {
	_, err := domain.GenerateSigningKey("")
	if err == nil {
		t.Fatal("expected error for empty kid, got nil")
	}
}

// --- KeySet ---

func TestNewKeySet_CurrentOnly(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")

	ks, err := domain.NewKeySet(current, nil, nil)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if ks.Current().KID != "kid-current" {
		t.Errorf("Current().KID = %q, want %q", ks.Current().KID, "kid-current")
	}
}

func TestNewKeySet_NilCurrent(t *testing.T) {
	_, err := domain.NewKeySet(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil current key, got nil")
	}
}

func TestKeySet_KeyByID_Current(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")
	ks, _ := domain.NewKeySet(current, nil, nil)

	got, err := ks.KeyByID("kid-current")
	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if !current.Public.Equal(got) {
		t.Error("returned public key does not match current")
	}
}

func TestKeySet_KeyByID_Retiring(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")
	retiring, _ := domain.GenerateSigningKey("kid-old")
	ks, _ := domain.NewKeySet(current, retiring, nil)

	got, err := ks.KeyByID("kid-old")
	if err != nil {
		t.Fatalf("KeyByID(retiring): %v", err)
	}
	if !retiring.Public.Equal(got) {
		t.Error("returned public key does not match retiring")
	}
}

func TestKeySet_KeyByID_Next(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")
	next, _ := domain.GenerateSigningKey("kid-next")
	ks, _ := domain.NewKeySet(current, nil, next)

	got, err := ks.KeyByID("kid-next")
	if err != nil {
		t.Fatalf("KeyByID(next): %v", err)
	}
	if !next.Public.Equal(got) {
		t.Error("returned public key does not match next")
	}
}

func TestKeySet_KeyByID_Unknown(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")
	ks, _ := domain.NewKeySet(current, nil, nil)

	_, err := ks.KeyByID("kid-bogus")
	if err == nil {
		t.Fatal("expected error for unknown kid, got nil")
	}
	if !errors.Is(err, domain.ErrUnknownKID) {
		t.Errorf("error = %v, want ErrUnknownKID", err)
	}
}

func TestKeySet_KeyByID_EmptyKID(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")
	ks, _ := domain.NewKeySet(current, nil, nil)

	_, err := ks.KeyByID("")
	if err == nil {
		t.Fatal("expected error for empty kid, got nil")
	}
}

// TestKeySet_PublicKeys returns every public key in the set — current + any
// non-nil retiring or next slots. This is the source for the JWKS endpoint
// (ADR-0008 / Task #10).
func TestKeySet_PublicKeys_AllSlots(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")
	retiring, _ := domain.GenerateSigningKey("kid-retiring")
	next, _ := domain.GenerateSigningKey("kid-next")
	ks, _ := domain.NewKeySet(current, retiring, next)

	keys := ks.PublicKeys()
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	// Order: current, retiring, next.
	want := []string{"kid-current", "kid-retiring", "kid-next"}
	for i, kid := range want {
		if keys[i].KID != kid {
			t.Errorf("keys[%d].KID = %q, want %q", i, keys[i].KID, kid)
		}
	}
}

func TestKeySet_PublicKeys_CurrentOnly(t *testing.T) {
	current, _ := domain.GenerateSigningKey("kid-current")
	ks, _ := domain.NewKeySet(current, nil, nil)

	keys := ks.PublicKeys()
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].KID != "kid-current" {
		t.Errorf("keys[0].KID = %q, want %q", keys[0].KID, "kid-current")
	}
}
