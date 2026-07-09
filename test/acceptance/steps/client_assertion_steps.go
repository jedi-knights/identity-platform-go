package steps

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// jwtBearerTestKID is the kid every fake JWKS server in this file
// advertises for its one signing key. A single fixed value is safe here
// because each scenario gets its own freshly-generated key and its own
// freshly-started JWKS server — there is no cross-scenario collision to
// worry about, mirroring introspectionSecret's documented rationale.
const jwtBearerTestKID = "test-kid"

// jwtBearerTestAudience is the aud value a client assertion must carry.
// Matches config.go's jwt.issuer default ("identity-platform") — none of
// this topology's env vars override AUTH_JWT_ISSUER.
const jwtBearerTestAudience = "identity-platform"

func registerClientAssertionSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	var signingKey *rsa.PrivateKey

	sctx.Step(`^a registered confidential OAuth client with scopes "([^"]*)", grant type "([^"]*)", and a JWT-bearer signing key$`,
		func(ctx context.Context, scopes, grantType string) error {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return fmt.Errorf("generating RSA key: %w", err)
			}
			signingKey = key
			jwksURL := startFakeJWKSServer(world(), &key.PublicKey)
			return registerClientWithJWKS(ctx, world(), scopes, grantType, jwksURL)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with a JWT-bearer assertion$`,
		func(ctx context.Context) error {
			w := world()
			assertion, err := signClientAssertion(signingKey, w.Vars["client_id"])
			if err != nil {
				return err
			}
			w.Vars["client_assertion"] = assertion
			return postClientAssertionToken(ctx, w, w.Vars["client_id"], assertion)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with a JWT-bearer assertion signed by a different key$`,
		func(ctx context.Context) error {
			wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return fmt.Errorf("generating RSA key: %w", err)
			}
			w := world()
			assertion, err := signClientAssertion(wrongKey, w.Vars["client_id"])
			if err != nil {
				return err
			}
			return postClientAssertionToken(ctx, w, w.Vars["client_id"], assertion)
		})

	sctx.Step(`^the client requests a token using the client_credentials grant with the same JWT-bearer assertion again$`,
		func(ctx context.Context) error {
			w := world()
			return postClientAssertionToken(ctx, w, w.Vars["client_id"], w.Vars["client_assertion"])
		})
}

// startFakeJWKSServer starts an httptest.Server serving a JWKS document
// with exactly one RSA key under jwtBearerTestKID, and registers its
// shutdown as a World cleanup. Returns the server's URL — the value the
// client registers as its jwks_uri.
func startFakeJWKSServer(world *support.World, pub *rsa.PublicKey) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": jwtBearerTestKID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigEndianBytes(pub.E)),
			}},
		})
	}))
	world.Cleanups = append(world.Cleanups, srv.Close)
	return srv.URL
}

// bigEndianBytes returns the minimal big-endian byte representation of e,
// matching the encoding auth-server's own JWKS handler uses.
func bigEndianBytes(e int) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(e))
	return new(big.Int).SetBytes(buf[:]).Bytes()
}

// registerClientWithJWKS calls client-registry-service's POST /clients
// with a jwks_uri, mirroring registerClient (client_credentials_steps.go)
// plus the one additional field neither that helper nor
// stepRegisterPublicClient (token_exchange_steps.go) covers.
func registerClientWithJWKS(ctx context.Context, world *support.World, scopesStr, grantType, jwksURI string) error {
	body := map[string]any{
		"name":        support.RandomID("acceptance-jwt-bearer-client"),
		"client_type": "confidential",
		"scopes":      strings.Fields(scopesStr),
		"grant_types": strings.Split(grantType, ","),
		"jwks_uri":    jwksURI,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshalling create-client request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["client-registry-service"].BaseURL+"/clients", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling client-registry-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var created struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return fmt.Errorf("decoding create-client response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create-client: want 201, got %d", resp.StatusCode)
	}

	world.Vars["client_id"] = created.ClientID
	return nil
}

// signClientAssertion builds and signs an RFC 7523 §3 client assertion:
// iss and sub both equal clientID, aud names this server's issuer, exp
// one minute out, and a fresh jti.
func signClientAssertion(key *rsa.PrivateKey, clientID string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{jwtBearerTestAudience},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        support.RandomID("jti"),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = jwtBearerTestKID
	return token.SignedString(key)
}

// postClientAssertionToken posts the client_credentials grant to
// auth-server's /oauth/token using an RFC 7523 client_assertion instead
// of a client_secret.
func postClientAssertionToken(ctx context.Context, world *support.World, clientID, assertion string) error {
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"read"},
	}
	return postToken(ctx, world, form)
}
