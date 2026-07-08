package application_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

const (
	testHTM = "POST"
	testHTU = "https://as.example.com/oauth/token"
)

// fakeDPoPProofRepo is a minimal in-test double — application_test cannot
// import the memory adapter package without creating an import cycle risk
// across module boundaries, and the real behavior (insert-if-absent, TTL'd)
// is already covered by memory.DPoPProofRepository's own tests.
type fakeDPoPProofRepo struct {
	seen map[string]time.Time
}

func newFakeDPoPProofRepo() *fakeDPoPProofRepo {
	return &fakeDPoPProofRepo{seen: make(map[string]time.Time)}
}

func (r *fakeDPoPProofRepo) MarkUsed(_ context.Context, jti string, expiresAt time.Time) error {
	if exp, ok := r.seen[jti]; ok && time.Now().Before(exp) {
		return domain.ErrDPoPProofReplayed
	}
	r.seen[jti] = expiresAt
	return nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ecJWKHeader builds the "jwk" header map for an EC P-256 public key. pub.Bytes
// returns the SEC1 uncompressed point (0x04 || X || Y); slicing it out avoids
// the deprecated direct pub.X/pub.Y field access.
func ecJWKHeader(pub *ecdsa.PublicKey) map[string]any {
	point, err := pub.Bytes()
	if err != nil {
		panic(err) // test fixture — a freshly generated key can never fail this
	}
	coordSize := (len(point) - 1) / 2
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64url(point[1 : 1+coordSize]),
		"y":   b64url(point[1+coordSize:]),
	}
}

// rsaJWKHeader builds the "jwk" header map for an RSA public key.
func rsaJWKHeader(pub *rsa.PublicKey) map[string]any {
	e := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"n":   b64url(pub.N.Bytes()),
		"e":   b64url(e),
	}
}

// signProof builds and signs a DPoP proof JWT, applying overrides to the
// registered claims/htm/htu/header before signing so individual tests can
// corrupt exactly one field.
func signProof(t *testing.T, method jwt.SigningMethod, key any, jwkHeader map[string]any, mutate func(claims jwt.MapClaims, header map[string]any)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"htm": testHTM,
		"htu": testHTU,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}
	header := map[string]any{
		"typ": "dpop+jwt",
		"jwk": jwkHeader,
	}
	if mutate != nil {
		mutate(claims, header)
	}
	token := jwt.NewWithClaims(method, claims)
	for k, v := range header {
		token.Header[k] = v
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing test proof: %v", err)
	}
	return signed
}

func newECKeyAndProof(t *testing.T, mutate func(jwt.MapClaims, map[string]any)) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	proof := signProof(t, jwt.SigningMethodES256, priv, ecJWKHeader(&priv.PublicKey), mutate)
	return priv, proof
}

func TestDPoPValidator_Validate_ValidECProof_ReturnsThumbprint(t *testing.T) {
	// Arrange
	priv, proof := newECKeyAndProof(t, nil)
	jwkHeader := ecJWKHeader(&priv.PublicKey)
	wantJWK := domain.JWK{Kty: "EC", Crv: "P-256", X: jwkHeader["x"].(string), Y: jwkHeader["y"].(string)}
	wantThumbprint, err := wantJWK.Thumbprint()
	if err != nil {
		t.Fatalf("computing expected thumbprint: %v", err)
	}
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	gotJKT, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotJKT != wantThumbprint {
		t.Errorf("jkt = %q, want %q", gotJKT, wantThumbprint)
	}
}

func TestDPoPValidator_Validate_ValidRSAProof_ReturnsThumbprint(t *testing.T) {
	// Arrange
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	proof := signProof(t, jwt.SigningMethodRS256, priv, rsaJWKHeader(&priv.PublicKey), nil)
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	gotJKT, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotJKT == "" {
		t.Error("expected a non-empty jkt")
	}
}

func TestDPoPValidator_Validate_WrongTyp_ReturnsError(t *testing.T) {
	// Arrange
	_, proof := newECKeyAndProof(t, func(_ jwt.MapClaims, header map[string]any) {
		header["typ"] = "JWT"
	})
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	_, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a wrong typ header")
	}
}

func TestDPoPValidator_Validate_MissingJWKHeader_ReturnsError(t *testing.T) {
	// Arrange
	_, proof := newECKeyAndProof(t, func(_ jwt.MapClaims, header map[string]any) {
		delete(header, "jwk")
	})
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	_, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a missing jwk header")
	}
}

func TestDPoPValidator_Validate_HTMMismatch_ReturnsError(t *testing.T) {
	// Arrange
	_, proof := newECKeyAndProof(t, func(claims jwt.MapClaims, _ map[string]any) {
		claims["htm"] = "GET"
	})
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	_, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for an htm mismatch")
	}
}

func TestDPoPValidator_Validate_HTUMismatch_ReturnsError(t *testing.T) {
	// Arrange
	_, proof := newECKeyAndProof(t, func(claims jwt.MapClaims, _ map[string]any) {
		claims["htu"] = "https://evil.example.com/oauth/token"
	})
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	_, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for an htu mismatch")
	}
}

func TestDPoPValidator_Validate_StaleIAT_ReturnsError(t *testing.T) {
	// Arrange
	_, proof := newECKeyAndProof(t, func(claims jwt.MapClaims, _ map[string]any) {
		claims["iat"] = time.Now().Add(-10 * time.Minute).Unix()
	})
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	_, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a stale iat")
	}
}

func TestDPoPValidator_Validate_MissingJTI_ReturnsError(t *testing.T) {
	// Arrange
	_, proof := newECKeyAndProof(t, func(claims jwt.MapClaims, _ map[string]any) {
		delete(claims, "jti")
	})
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	_, err := v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a missing jti")
	}
}

func TestDPoPValidator_Validate_ReplayedJTI_ReturnsError(t *testing.T) {
	// Arrange
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	claims := jwt.MapClaims{"htm": testHTM, "htu": testHTU, "iat": time.Now().Unix(), "jti": "fixed-jti"}
	header := map[string]any{"typ": "dpop+jwt", "jwk": ecJWKHeader(&priv.PublicKey)}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	for k, val := range header {
		token.Header[k] = val
	}
	proof, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing proof: %v", err)
	}
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())
	if _, err := v.Validate(context.Background(), proof, testHTM, testHTU); err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}

	// Act
	_, err = v.Validate(context.Background(), proof, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a replayed jti")
	}
}

func TestDPoPValidator_Validate_TamperedSignature_ReturnsError(t *testing.T) {
	// Arrange
	_, proof := newECKeyAndProof(t, nil)
	tampered := proof[:len(proof)-4] + "abcd"
	v := application.NewDPoPValidator(newFakeDPoPProofRepo())

	// Act
	_, err := v.Validate(context.Background(), tampered, testHTM, testHTU)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a tampered signature")
	}
}
