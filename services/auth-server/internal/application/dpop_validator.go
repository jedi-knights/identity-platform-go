package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// dpopProofFreshnessWindow bounds how old a DPoP proof's iat may be (RFC
// 9449 §11.1 recommends a short window; the exact duration is left to
// deployments). Also used as the replay-cache TTL — once a proof falls
// outside this window it fails the freshness check regardless of jti, so
// there is nothing left to protect by remembering it longer.
const dpopProofFreshnessWindow = 5 * time.Minute

// dpopClaims is the RFC 9449 §4.2 proof claim set: registered iat/jti plus
// htm/htu. Deliberately not embedding jwt.RegisteredClaims — DPoP proofs
// don't use iss/sub/aud/exp, and MapClaims-style access keeps htm/htu/iat/jti
// extraction uniform in Validate below.
type dpopClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
}

func (c *dpopClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }

func (c *dpopClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IAT, 0)), nil
}

func (c *dpopClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c *dpopClaims) GetIssuer() (string, error)              { return "", nil }
func (c *dpopClaims) GetSubject() (string, error)             { return "", nil }
func (c *dpopClaims) GetAudience() (jwt.ClaimStrings, error)  { return nil, nil }

// DPoPValidator validates RFC 9449 DPoP proof JWTs presented at the token
// endpoint (ADR-0025). Grant-agnostic — the same validator serves every
// grant type; Handler.Token calls it once before dispatching to a
// GrantStrategy.
type DPoPValidator struct {
	replayRepo domain.DPoPProofRepository
}

// NewDPoPValidator wires a DPoPValidator against the given replay cache.
func NewDPoPValidator(replayRepo domain.DPoPProofRepository) *DPoPValidator {
	return &DPoPValidator{replayRepo: replayRepo}
}

// keyfuncFromHeader returns a jwt.Keyfunc that requires typ:"dpop+jwt" and a
// "jwk" header (RFC 9449 §4.2 — a kid-only or x5c header is not a DPoP
// proof), decodes that jwk into out, and returns its public key for
// signature verification. Extracted from Validate to keep gocyclo in
// budget.
func keyfuncFromHeader(out *domain.JWK) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		if t.Header["typ"] != "dpop+jwt" {
			return nil, fmt.Errorf("dpop: typ header must be %q", "dpop+jwt")
		}
		jwkHeader, ok := t.Header["jwk"]
		if !ok {
			return nil, errors.New("dpop: proof header missing jwk")
		}
		raw, err := json.Marshal(jwkHeader)
		if err != nil {
			return nil, fmt.Errorf("dpop: re-marshaling jwk header: %w", err)
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fmt.Errorf("dpop: decoding jwk header: %w", err)
		}
		return out.PublicKey()
	}
}

// Validate parses and verifies proofJWT, checking it against htm (the HTTP
// method of the request being proved) and htu (that request's URL, without
// query or fragment, per RFC 9449 §4.3). Returns the RFC 7638 thumbprint of
// the proof's embedded public key on success.
func (v *DPoPValidator) Validate(ctx context.Context, proofJWT, htm, htu string) (string, error) {
	var jwk domain.JWK
	token, err := jwt.ParseWithClaims(proofJWT, &dpopClaims{}, keyfuncFromHeader(&jwk),
		jwt.WithValidMethods(domain.SupportedDPoPSigningAlgs))
	if err != nil {
		return "", fmt.Errorf("dpop: invalid proof: %w", err)
	}

	claims, ok := token.Claims.(*dpopClaims)
	if !ok {
		return "", errors.New("dpop: unexpected claims type")
	}
	if err := v.validateClaims(claims, htm, htu); err != nil {
		return "", err
	}

	jkt, err := jwk.Thumbprint()
	if err != nil {
		return "", fmt.Errorf("dpop: computing thumbprint: %w", err)
	}

	if err := v.replayRepo.MarkUsed(ctx, claims.JTI, time.Unix(claims.IAT, 0).Add(dpopProofFreshnessWindow)); err != nil {
		return "", fmt.Errorf("dpop: %w", err)
	}

	return jkt, nil
}

func (v *DPoPValidator) validateClaims(claims *dpopClaims, htm, htu string) error {
	if claims.HTM != htm {
		return fmt.Errorf("dpop: htm %q does not match request method %q", claims.HTM, htm)
	}
	if claims.HTU != htu {
		return fmt.Errorf("dpop: htu %q does not match request URL %q", claims.HTU, htu)
	}
	if claims.JTI == "" {
		return errors.New("dpop: proof missing jti")
	}
	iat := time.Unix(claims.IAT, 0)
	if claims.IAT == 0 || time.Since(iat) > dpopProofFreshnessWindow || time.Since(iat) < -dpopProofFreshnessWindow {
		return errors.New("dpop: proof iat outside the freshness window")
	}
	return nil
}
