package domain

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ErrDPoPProofReplayed is returned by DPoPProofRepository.MarkUsed when a
// proof's jti was already marked used within its validity window (RFC 9449
// §11.1).
var ErrDPoPProofReplayed = errors.New("dpop proof replayed")

// DPoPProofRepository records DPoP proof jti values so a proof cannot be
// replayed within its freshness window (ADR-0025). Unlike
// AuthorizationCodeRepository.Consume (read-and-delete, single use), this is
// "insert-if-absent, TTL'd" — a jti is remembered until expiresAt, then may
// be forgotten (and, if ever reused after that point, would incorrectly
// succeed — but by then the proof itself has failed the iat freshness check
// anyway, so this is not a real gap).
type DPoPProofRepository interface {
	// MarkUsed records jti as used until expiresAt. Returns
	// ErrDPoPProofReplayed if jti is already recorded and has not expired.
	MarkUsed(ctx context.Context, jti string, expiresAt time.Time) error
}

// JWK is a decode-only view of the RFC 7517/7518 members a DPoP proof's
// embedded "jwk" header parameter carries. It intentionally covers only the
// EC (P-256) and RSA member sets DPoP proofs use — not the full JWK spec.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// PublicKey decodes j into a crypto.PublicKey. Supports "EC" (P-256 only)
// and "RSA". Returns an error for any other kty or an unsupported curve.
func (j JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "EC":
		return j.ecPublicKey()
	case "RSA":
		return j.rsaPublicKey()
	default:
		return nil, fmt.Errorf("dpop: unsupported jwk kty %q", j.Kty)
	}
}

// ecP256CoordSize is the fixed big-endian octet length of a P-256
// coordinate (RFC 7518 §6.2.1.2) — 256 bits.
const ecP256CoordSize = 32

func (j JWK) ecPublicKey() (*ecdsa.PublicKey, error) {
	if j.Crv != "P-256" {
		return nil, fmt.Errorf("dpop: unsupported jwk crv %q", j.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("dpop: decoding jwk x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("dpop: decoding jwk y: %w", err)
	}
	// Build the SEC1 uncompressed point (0x04 || X || Y) rather than
	// assigning X/Y on an ecdsa.PublicKey directly — Go 1.26 deprecated
	// that in favor of ParseUncompressedPublicKey/Bytes.
	point := make([]byte, 0, 1+2*ecP256CoordSize)
	point = append(point, 0x04)
	point = append(point, leftPad(x, ecP256CoordSize)...)
	point = append(point, leftPad(y, ecP256CoordSize)...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

// leftPad zero-pads b on the left to size bytes. RFC 7518 §6.2.1.2 requires
// EC coordinates to be fixed-length octet strings; a conforming encoder
// never trims leading zero bytes, but this guards against one that does.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func (j JWK) rsaPublicKey() (*rsa.PublicKey, error) {
	n, err := decodeBase64URLBigInt(j.N)
	if err != nil {
		return nil, fmt.Errorf("dpop: decoding jwk n: %w", err)
	}
	e, err := decodeBase64URLBigInt(j.E)
	if err != nil {
		return nil, fmt.Errorf("dpop: decoding jwk e: %w", err)
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// Thumbprint computes the RFC 7638 §3.2 JWK thumbprint: SHA-256 over the
// canonical JSON of only the required members, in lexicographic key order,
// with no whitespace. base64url-encoded without padding.
func (j JWK) Thumbprint() (string, error) {
	var canonical []byte
	var err error
	switch j.Kty {
	case "EC":
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{j.Crv, j.Kty, j.X, j.Y})
	case "RSA":
		canonical, err = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{j.E, j.Kty, j.N})
	default:
		return "", fmt.Errorf("dpop: unsupported jwk kty %q", j.Kty)
	}
	if err != nil {
		return "", fmt.Errorf("dpop: marshaling canonical jwk: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func decodeBase64URLBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
