package steps

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// registerDPoPSteps wires the RFC 9449 (ADR-0025 in identity-platform-go's
// auth-server) steps for the auth-server-side round trip: a real DPoP
// proof presented at /oauth/token, the issued token's type, and the
// resulting cnf.jkt echoed by introspection.
func registerDPoPSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client requests a token using the client_credentials grant with scope "([^"]*)" and a valid DPoP proof$`,
		func(ctx context.Context, scope string) error {
			return stepRequestClientCredentialsTokenWithDPoP(ctx, world(), scope, true)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with scope "([^"]*)" and a DPoP proof for the wrong endpoint$`,
		func(ctx context.Context, scope string) error {
			return stepRequestClientCredentialsTokenWithDPoP(ctx, world(), scope, false)
		})

	sctx.Step(`^the response's cnf\.jkt is non-empty$`, func() error {
		return stepAssertCNFJKTNonEmpty(world())
	})
}

// stepRequestClientCredentialsTokenWithDPoP generates a fresh ES256 key,
// signs a DPoP proof for POST <auth-server>/oauth/token, and posts the
// client_credentials request with that proof in the DPoP header — mirroring
// how PKCE scenarios generate their own code_verifier/code_challenge rather
// than depending on a fixture. When validHTU is false, the proof is signed
// for a different (wrong) endpoint so auth-server's htu check rejects it.
func stepRequestClientCredentialsTokenWithDPoP(ctx context.Context, world *support.World, scope string, validHTU bool) error {
	htu := world.Services["auth-server"].BaseURL + "/oauth/token"
	if !validHTU {
		htu = "http://wrong-host.example.com/oauth/token"
	}
	proof, err := buildDPoPProof(htu)
	if err != nil {
		return fmt.Errorf("building dpop proof: %w", err)
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {world.Vars["client_id"]},
		"client_secret": {world.Vars["client_secret"]},
		"scope":         {scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["auth-server"].BaseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling auth-server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading auth-server response body: %w", err)
	}
	world.LastResponse = resp
	world.LastBody = body
	return nil
}

// buildDPoPProof signs a fresh ES256 DPoP proof for POST htu, exactly what
// a real DPoP client presents at the token endpoint (RFC 9449 §4).
func buildDPoPProof(htu string) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generating EC key: %w", err)
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		return "", fmt.Errorf("encoding EC public key: %w", err)
	}
	coordSize := (len(point) - 1) / 2
	enc := base64.RawURLEncoding.EncodeToString
	claims := jwt.MapClaims{
		"htm": http.MethodPost,
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": support.RandomID("dpop-jti"),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   enc(point[1 : 1+coordSize]),
		"y":   enc(point[1+coordSize:]),
	}
	return token.SignedString(priv)
}

// stepAssertCNFJKTNonEmpty checks the nested RFC 7800 "cnf":{"jkt":...}
// claim — the generic stepAssertNonEmpty only reads top-level fields.
func stepAssertCNFJKTNonEmpty(world *support.World) error {
	var decoded struct {
		CNF *struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	if decoded.CNF == nil || decoded.CNF.JKT == "" {
		return fmt.Errorf("expected a non-empty cnf.jkt — body: %s", world.LastBody)
	}
	return nil
}
