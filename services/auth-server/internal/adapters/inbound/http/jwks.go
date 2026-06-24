package http

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// JWKSHandler serves the JWKS document at /.well-known/jwks.json per RFC 7517.
//
// The handler is read-only and stateless — it derives every byte of the
// response from the KeySet on every request. There is no caching layer here;
// HTTP caching is the client's job via the Cache-Control header below.
//
// Security: the handler MUST NOT serialise any private-key field. The JWK
// encoder uses an explicit allow-list of fields (kty, use, alg, kid, n, e),
// so adding a new private RSA component to domain.SigningKey cannot
// accidentally leak through this surface.
type JWKSHandler struct {
	keys *domain.KeySet
}

// NewJWKSHandler wires the handler to the auth-server's KeySet. Nil is a
// programmer error — surface the failure here, not at first request.
func NewJWKSHandler(keys *domain.KeySet) *JWKSHandler {
	if keys == nil {
		panic("NewJWKSHandler: keys must not be nil")
	}
	return &JWKSHandler{keys: keys}
}

// jwk is the public RSA JWK shape per RFC 7517 §4 + RFC 7518 §6.3.1. Only
// these fields are emitted — never `d`, `p`, `q`, `dp`, `dq`, `qi` (the
// private components).
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// Get returns the JWKS document. Cache-Control matches the 1-hour TTL
// described in ADR-0008 and the JWKS-fetcher's default cache window.
//
// @Summary      JWKS endpoint
// @Description  Public keys for verifying RS256-signed access tokens (RFC 7517).
// @Tags         oauth
// @Produce      application/jwk-set+json
// @Success      200  {object}  map[string]any
// @Router       /.well-known/jwks.json [get]
func (h *JWKSHandler) Get(w http.ResponseWriter, _ *http.Request) {
	body := jwks{Keys: make([]jwk, 0, 3)}
	for _, sk := range h.keys.PublicKeys() {
		body.Keys = append(body.Keys, encodeJWK(sk))
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// At this point headers are already written; the connection will
		// be torn down by the server. Nothing to recover.
		http.Error(w, "encoding jwks", http.StatusInternalServerError)
	}
}

// encodeJWK projects a SigningKey to its public JWK form. base64url without
// padding per RFC 7515 §2.
func encodeJWK(sk *domain.SigningKey) jwk {
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: sk.KID,
		N:   base64.RawURLEncoding.EncodeToString(sk.Public.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigEndianBytes(sk.Public.E)),
	}
}

// bigEndianBytes returns the minimal big-endian byte representation of e.
// For the common RSA exponent 65537 this is [0x01, 0x00, 0x01] → "AQAB".
// Uses encoding/binary to put 4 bytes, then strips leading zero bytes.
func bigEndianBytes(e int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(e))
	// Strip leading zeros; a big.Int conversion would also work but adds
	// allocation churn for what is almost always a 3-byte output.
	return new(big.Int).SetBytes(buf[:]).Bytes()
}
