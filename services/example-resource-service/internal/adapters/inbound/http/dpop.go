// RFC 9449 (DPoP) resource-server-side proof-of-possession enforcement.
//
// This deliberately duplicates a small amount of JWK-decode/thumbprint and
// proof-parsing logic already present in auth-server's domain.JWK and
// application.DPoPValidator (ADR-0025 in identity-platform-go's auth-server)
// rather than sharing it — these are two separate Go modules in this
// workspace with no existing shared-code mechanism beyond the external
// go-platform module this ADR does not extend. "A little copying is better
// than a little dependency."
//
// Scope cut, stated in the ADR: no jti replay cache at this layer. RFC 9449
// §7.1 phrases resource-server replay protection as SHOULD, not MUST; the
// higher-value replay target is the token endpoint (auth-server), which
// does have a replay cache.
package http

import (
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
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/httputil"
)

// dpopProofFreshnessWindow mirrors auth-server's DPoPValidator constant —
// see ADR-0025 for why this value is hardcoded rather than configurable.
const dpopProofFreshnessWindow = 5 * time.Minute

// jwk is a decode-only view of the JWK members a DPoP proof's "jwk" header
// carries. Mirrors auth-server's domain.JWK.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

const ecP256CoordSize = 32

func (j jwk) publicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "EC":
		return j.ecPublicKey()
	case "RSA":
		return j.rsaPublicKey()
	default:
		return nil, fmt.Errorf("dpop: unsupported jwk kty %q", j.Kty)
	}
}

func (j jwk) ecPublicKey() (*ecdsa.PublicKey, error) {
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
	point := make([]byte, 0, 1+2*ecP256CoordSize)
	point = append(point, 0x04)
	point = append(point, leftPad(x, ecP256CoordSize)...)
	point = append(point, leftPad(y, ecP256CoordSize)...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

func (j jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("dpop: decoding jwk n: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("dpop: decoding jwk e: %w", err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// jwkThumbprint computes the RFC 7638 thumbprint of a decoded "jwk" header
// (as a generic map, exactly how it arrives on jwt.Token.Header).
func jwkThumbprint(header map[string]any) (string, error) {
	raw, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("dpop: re-marshaling jwk header: %w", err)
	}
	var j jwk
	if err := json.Unmarshal(raw, &j); err != nil {
		return "", fmt.Errorf("dpop: decoding jwk header: %w", err)
	}
	var canonical []byte
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

// dpopProofClaims is the RFC 9449 §4.2 proof claim set this resource server
// checks: htm/htu/iat. jti is read but not tracked for replay (stated ADR
// scope cut).
type dpopProofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
}

func (c *dpopProofClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (c *dpopProofClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IAT, 0)), nil
}
func (c *dpopProofClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c *dpopProofClaims) GetIssuer() (string, error)              { return "", nil }
func (c *dpopProofClaims) GetSubject() (string, error)             { return "", nil }
func (c *dpopProofClaims) GetAudience() (jwt.ClaimStrings, error)  { return nil, nil }

// dpopKeyfunc returns a jwt.Keyfunc requiring typ:"dpop+jwt" and a "jwk"
// header, decoding that jwk into *jwkHeader as a side effect so the caller
// can compute its thumbprint after a successful parse.
func dpopKeyfunc(jwkHeader *map[string]any) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		if t.Header["typ"] != "dpop+jwt" {
			return nil, fmt.Errorf("dpop: typ header must be %q", "dpop+jwt")
		}
		raw, ok := t.Header["jwk"]
		if !ok {
			return nil, errors.New("dpop: proof header missing jwk")
		}
		asMap, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("dpop: jwk header is not an object")
		}
		*jwkHeader = asMap
		marshaled, err := json.Marshal(asMap)
		if err != nil {
			return nil, fmt.Errorf("dpop: re-marshaling jwk header: %w", err)
		}
		var j jwk
		if err := json.Unmarshal(marshaled, &j); err != nil {
			return nil, fmt.Errorf("dpop: decoding jwk header: %w", err)
		}
		return j.publicKey()
	}
}

// checkDPoPClaims validates htm/htu/iat against the live request. jti is
// deliberately not checked for replay here (stated ADR scope cut).
func checkDPoPClaims(claims *dpopProofClaims, htm, htu string) error {
	if claims.HTM != htm {
		return fmt.Errorf("dpop: htm %q does not match request method %q", claims.HTM, htm)
	}
	if claims.HTU != htu {
		return fmt.Errorf("dpop: htu %q does not match request URL %q", claims.HTU, htu)
	}
	iat := time.Unix(claims.IAT, 0)
	if claims.IAT == 0 || time.Since(iat) > dpopProofFreshnessWindow || time.Since(iat) < -dpopProofFreshnessWindow {
		return errors.New("dpop: proof iat outside the freshness window")
	}
	return nil
}

// validateDPoPProof parses and verifies proofJWT against htm/htu, returning
// the RFC 7638 thumbprint of its embedded key on success. Mirrors
// auth-server's application.DPoPValidator.Validate, minus the jti replay
// check (stated ADR scope cut for this layer).
func validateDPoPProof(proofJWT, htm, htu string) (string, error) {
	var jwkHeader map[string]any
	token, err := jwt.ParseWithClaims(proofJWT, &dpopProofClaims{}, dpopKeyfunc(&jwkHeader),
		jwt.WithValidMethods([]string{"ES256", "RS256"}))
	if err != nil {
		return "", fmt.Errorf("dpop: invalid proof: %w", err)
	}

	claims, ok := token.Claims.(*dpopProofClaims)
	if !ok {
		return "", errors.New("dpop: unexpected claims type")
	}
	if err := checkDPoPClaims(claims, htm, htu); err != nil {
		return "", err
	}

	return jwkThumbprint(jwkHeader)
}

// requestURL reconstructs the request's URL — scheme, host, path, no query
// or fragment — for RFC 9449 §4.3 htu comparison, mirroring auth-server's
// own requestURL helper exactly (handler.go).
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// RequireDPoPMiddleware enforces RFC 9449 §7.1 proof-of-possession: whenever
// the context's confirmed jkt (populated by IntrospectionAuthMiddleware
// from the token's cnf.jkt) is non-empty, this request's own DPoP header
// must present a valid proof whose key thumbprint matches. A no-op for
// ordinary bearer tokens (empty jkt) — unlike RequireScopeMiddleware /
// RequireACRMiddleware, there is no route-level "requiredness" parameter;
// enforcement is driven entirely by whether the token itself is bound.
func RequireDPoPMiddleware(logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jkt, _ := r.Context().Value(contextKeyCNFJKT).(string)
			if jkt == "" {
				next.ServeHTTP(w, r)
				return
			}
			proof := r.Header.Get("DPoP")
			if proof == "" {
				writeDPoPChallenge(w, "missing DPoP proof for a DPoP-bound token")
				return
			}
			gotJKT, err := validateDPoPProof(proof, r.Method, requestURL(r))
			if err != nil {
				logger.Warn("dpop proof rejected", "error", err)
				writeDPoPChallenge(w, "invalid DPoP proof")
				return
			}
			if gotJKT != jkt {
				writeDPoPChallenge(w, "DPoP proof key does not match the token's confirmed key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeDPoPChallenge writes the RFC 9449 §7.1 challenge — scheme "DPoP",
// not "Bearer" — for a rejected or missing proof.
func writeDPoPChallenge(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate",
		`DPoP algs="ES256 RS256", error="invalid_token", error_description="`+description+`"`)
	httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, description))
}
