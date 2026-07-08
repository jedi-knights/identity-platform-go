package domain_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// generateECJWK generates a fresh P-256 key and returns its public
// coordinates as a domain.JWK. Used instead of a hand-copied literal
// test vector — ecdsa.ParseUncompressedPublicKey validates the point is
// actually on the curve, and a slightly-misremembered literal fails that
// check outright rather than silently producing a wrong-but-plausible key.
func generateECJWK(t *testing.T) domain.JWK {
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
	return domain.JWK{Kty: "EC", Crv: "P-256", X: enc(point[1 : 1+coordSize]), Y: enc(point[1+coordSize:])}
}

// TestJWK_Thumbprint_RSA_MatchesRFC7638Vector uses the exact worked example
// from RFC 7638 Appendix A — a known-good input/output pair that pins the
// canonicalization (member order, no whitespace) rather than just checking
// that some hash comes out.
func TestJWK_Thumbprint_RSA_MatchesRFC7638Vector(t *testing.T) {
	// Arrange
	jwk := domain.JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}

	// Act
	got, err := jwk.Thumbprint()

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Errorf("Thumbprint() = %q, want %q", got, want)
	}
}

func TestJWK_Thumbprint_EC_DeterministicAndDistinctPerKey(t *testing.T) {
	// Arrange
	a := generateECJWK(t)
	b := generateECJWK(t)

	// Act
	got1, err1 := a.Thumbprint()
	got2, err2 := a.Thumbprint()
	gotB, errB := b.Thumbprint()

	// Assert
	if err1 != nil || err2 != nil || errB != nil {
		t.Fatalf("unexpected errors: %v %v %v", err1, err2, errB)
	}
	if got1 != got2 {
		t.Errorf("Thumbprint() not deterministic: %q != %q", got1, got2)
	}
	if got1 == gotB {
		t.Errorf("distinct keys produced the same thumbprint: %q", got1)
	}
}

func TestJWK_PublicKey_EC_RoundTrips(t *testing.T) {
	// Arrange
	jwk := generateECJWK(t)

	// Act
	pub, err := jwk.PublicKey()

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub == nil {
		t.Fatal("expected a non-nil public key")
	}
}

func TestJWK_PublicKey_RSA_RoundTrips(t *testing.T) {
	// Arrange
	jwk := domain.JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}

	// Act
	pub, err := jwk.PublicKey()

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub == nil {
		t.Fatal("expected a non-nil public key")
	}
}

func TestJWK_PublicKey_UnsupportedKty_ReturnsError(t *testing.T) {
	// Arrange
	jwk := domain.JWK{Kty: "oct"}

	// Act
	_, err := jwk.PublicKey()

	// Assert
	if err == nil {
		t.Fatal("expected an error for an unsupported kty")
	}
}

func TestJWK_PublicKey_UnsupportedCurve_ReturnsError(t *testing.T) {
	// Arrange
	jwk := domain.JWK{Kty: "EC", Crv: "P-521", X: "AA", Y: "AA"}

	// Act
	_, err := jwk.PublicKey()

	// Assert
	if err == nil {
		t.Fatal("expected an error for an unsupported curve")
	}
}
