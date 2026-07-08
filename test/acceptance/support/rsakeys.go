package support

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// rsaKeyBits matches the RS256 minimum key size (RFC 7518 §3.3) that
// auth-server's domain.LoadSigningKey enforces — a smaller test key would
// be rejected at auth-server startup.
const rsaKeyBits = 2048

// GenerateRSAKeyPEM generates a fresh RSA keypair and PEM-encodes the
// private half as PKCS#1 ("-----BEGIN RSA PRIVATE KEY-----"), the format
// `openssl genrsa` produces and one of the two formats auth-server's
// domain.LoadSigningKey accepts. Used to populate AUTH_JWT_RSA_PRIVATE_KEY_PEM*
// env vars for scenarios exercising the ADR-0008 key-rotation window.
func GenerateRSAKeyPEM() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return "", fmt.Errorf("generating RSA key: %w", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block)), nil
}
