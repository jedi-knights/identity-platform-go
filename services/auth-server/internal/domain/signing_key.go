package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// rs256MinKeyBits is the minimum RSA key size for RS256 access tokens
// (RFC 7518 §3.3 — "a key of size 2048 bits or larger MUST be used").
const rs256MinKeyBits = 2048

// ErrUnknownKID is returned by KeySet.KeyByID when no key in the set matches
// the requested kid. The JWKS verifier maps this to ErrTokenInvalid for the
// fail-closed behaviour required by ADR-0008.
var ErrUnknownKID = errors.New("unknown kid")

// SigningKey is an RSA keypair bound to a stable kid identifier used in the
// JOSE header of every token signed with it. The KID is the join key between
// signing time and verification time — the JWKS endpoint advertises it; the
// keyfunc resolves it back to Public.
type SigningKey struct {
	KID     string
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// LoadSigningKey parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8) and
// binds it to the supplied kid. Rejects keys below the 2048-bit floor.
func LoadSigningKey(pemStr, kid string) (*SigningKey, error) {
	if pemStr == "" {
		return nil, errors.New("loading signing key: pem must not be empty")
	}
	if kid == "" {
		return nil, errors.New("loading signing key: kid must not be empty")
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("loading signing key: no PEM block found")
	}
	priv, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("loading signing key: %w", err)
	}
	if bits := priv.N.BitLen(); bits < rs256MinKeyBits {
		return nil, fmt.Errorf("loading signing key: key size %d bits below RS256 minimum %d (RFC 7518 §3.3)", bits, rs256MinKeyBits)
	}
	return &SigningKey{KID: kid, Private: priv, Public: &priv.PublicKey}, nil
}

// parsePrivateKey accepts either PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`)
// or PKCS#8 (`-----BEGIN PRIVATE KEY-----`) DER bytes. Operators commonly
// produce PKCS#1 with `openssl genrsa` and PKCS#8 with `openssl genpkey`;
// supporting both avoids forcing a re-encode step at deploy time.
func parsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if priv, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return priv, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing as PKCS#1 or PKCS#8: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is %T, want *rsa.PrivateKey", parsed)
	}
	return priv, nil
}

// GenerateSigningKey produces a fresh 2048-bit RSA keypair bound to the
// supplied kid. The keypair lives in memory only — operators wanting
// persistence across restarts must supply AUTH_RSA_PRIVATE_KEY_PEM and use
// LoadSigningKey instead.
func GenerateSigningKey(kid string) (*SigningKey, error) {
	if kid == "" {
		return nil, errors.New("generating signing key: kid must not be empty")
	}
	priv, err := rsa.GenerateKey(rand.Reader, rs256MinKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}
	return &SigningKey{KID: kid, Private: priv, Public: &priv.PublicKey}, nil
}

// KeySet holds the live RSA keys auth-server uses. Current is the only key
// used to *sign* new tokens. Retiring (the previous current) and Next (a
// pre-staged successor) are present in the JWKS for verifier-side discovery
// during the rotation window described in ADR-0008.
type KeySet struct {
	current  *SigningKey
	retiring *SigningKey // optional
	next     *SigningKey // optional
}

// NewKeySet builds a KeySet from current + optional retiring + optional next.
// Returns an error if current is nil — there must always be one signing key.
func NewKeySet(current, retiring, next *SigningKey) (*KeySet, error) {
	if current == nil {
		return nil, errors.New("new keyset: current key must not be nil")
	}
	return &KeySet{current: current, retiring: retiring, next: next}, nil
}

// Current returns the active signing key — the one new tokens are signed with.
func (k *KeySet) Current() *SigningKey { return k.current }

// KeyByID resolves a kid to its public verification key. Returns ErrUnknownKID
// when no slot in the set matches. Empty kid is rejected at the boundary.
func (k *KeySet) KeyByID(kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("keyset: kid must not be empty")
	}
	for _, sk := range [...]*SigningKey{k.current, k.retiring, k.next} {
		if sk != nil && sk.KID == kid {
			return sk.Public, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
}

// PublicKeys returns every signing key in the set in order: current, retiring,
// next. Nil slots are skipped. Used to build the JWKS document (ADR-0008 / Task #10).
func (k *KeySet) PublicKeys() []*SigningKey {
	out := make([]*SigningKey, 0, 3)
	for _, sk := range [...]*SigningKey{k.current, k.retiring, k.next} {
		if sk != nil {
			out = append(out, sk)
		}
	}
	return out
}
