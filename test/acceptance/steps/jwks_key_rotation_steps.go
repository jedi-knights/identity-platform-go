package steps

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/jedi-knights/go-platform/jwtutil"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// jwk mirrors the public RSA JWK shape auth-server's JWKSHandler emits
// (RFC 7517 §4 + RFC 7518 §6.3.1) — kty, use, alg, kid, n, e only, never a
// private component.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

func registerJWKSKeyRotationSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client fetches the JWKS document$`, func(ctx context.Context) error {
		return stepFetchJWKS(ctx, world())
	})

	sctx.Step(`^the JWKS document contains exactly (\d+) keys?$`, func(count int) error {
		return stepAssertJWKSKeyCount(world(), count)
	})

	sctx.Step(`^the JWKS document does not expose any private key material$`, func() error {
		return stepAssertNoPrivateKeyMaterial(world())
	})

	sctx.Step(`^the JWKS document's key ids are "([^"]*)" in order$`, func(idsCSV string) error {
		return stepAssertJWKSKeyIDOrder(world(), idsCSV)
	})

	sctx.Step(`^the access token's kid header is one of the JWKS document's key ids$`, func() error {
		return stepAssertAccessTokenKidInJWKS(world())
	})

	sctx.Step(`^the client introspects a forged HS256-signed access token$`, func(ctx context.Context) error {
		return stepIntrospectForgedHS256Token(ctx, world())
	})
}

// stepFetchJWKS calls auth-server's unauthenticated GET /.well-known/jwks.json
// and stores the response for the generic common_steps assertions plus this
// file's JWKS-specific ones.
func stepFetchJWKS(ctx context.Context, world *support.World) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		world.Services["auth-server"].BaseURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return err
	}

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	world.LastResponse = resp
	world.LastBody = body
	return nil
}

func decodeJWKS(world *support.World) (*jwksDoc, error) {
	var doc jwksDoc
	if err := json.Unmarshal(world.LastBody, &doc); err != nil {
		return nil, fmt.Errorf("decoding JWKS document: %w — body: %s", err, world.LastBody)
	}
	return &doc, nil
}

func stepAssertJWKSKeyCount(world *support.World, want int) error {
	doc, err := decodeJWKS(world)
	if err != nil {
		return err
	}
	if len(doc.Keys) != want {
		return fmt.Errorf("JWKS key count: want %d, got %d — body: %s", want, len(doc.Keys), world.LastBody)
	}
	return nil
}

// stepAssertNoPrivateKeyMaterial mirrors auth-server's own
// TestJWKSHandler_DoesNotExposePrivateKey — the private RSA components
// (d, p, q, dp, dq, qi per RFC 7517 §4) must never appear in a public JWK.
func stepAssertNoPrivateKeyMaterial(world *support.World) error {
	forbidden := []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`, "PRIVATE"}
	body := string(world.LastBody)
	for _, f := range forbidden {
		if strings.Contains(body, f) {
			return fmt.Errorf("JWKS document unexpectedly contains %q — private key material may be leaking: %s", f, body)
		}
	}
	return nil
}

func stepAssertJWKSKeyIDOrder(world *support.World, idsCSV string) error {
	doc, err := decodeJWKS(world)
	if err != nil {
		return err
	}
	want := strings.Split(idsCSV, ", ")
	got := make([]string, len(doc.Keys))
	for i, k := range doc.Keys {
		got[i] = k.Kid
	}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		return fmt.Errorf("JWKS key id order: want %v, got %v", want, got)
	}
	return nil
}

func stepAssertAccessTokenKidInJWKS(world *support.World) error {
	kid, err := jwtKidHeader(world.Vars["access_token"])
	if err != nil {
		return err
	}
	doc, err := decodeJWKS(world)
	if err != nil {
		return err
	}
	for _, k := range doc.Keys {
		if k.Kid == kid {
			return nil
		}
	}
	return fmt.Errorf("access token kid %q not found among JWKS key ids in: %s", kid, world.LastBody)
}

// jwtKidHeader decodes a JWT's header segment (base64url, unverified) and
// returns its kid. Unverified decoding is safe here — the token was just
// issued to us by auth-server in this same scenario, so the only question
// being asked is whether auth-server's own JWKS advertises the kid it
// signed with, not whether the signature is trustworthy.
func jwtKidHeader(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT: want 3 dot-separated parts, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decoding JWT header: %w", err)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("unmarshalling JWT header: %w", err)
	}
	return header.Kid, nil
}

// stepIntrospectForgedHS256Token signs a token with jwtutil.Sign (HS256)
// under an attacker-controlled secret that auth-server never saw, then
// presents it to /oauth/introspect. auth-server is configured for RS256
// (the ADR-0008 default), so jwtutil.ParseRS256's algorithm-confusion
// defense (RFC 8725 §3.1) must reject it outright — RFC 7662 §2.2 requires
// this to still land as HTTP 200 with active:false, never a 4xx/5xx.
func stepIntrospectForgedHS256Token(ctx context.Context, world *support.World) error {
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "attacker",
		Subject:   world.Vars["client_id"],
		ClientID:  world.Vars["client_id"],
		Scope:     "read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
	forged, err := jwtutil.Sign(claims, []byte("attacker-controlled-hmac-secret-not-known-to-auth-server"))
	if err != nil {
		return fmt.Errorf("forging HS256 token: %w", err)
	}
	return stepIntrospect(ctx, world, world.Vars["client_id"], world.Vars["client_secret"], forged)
}
