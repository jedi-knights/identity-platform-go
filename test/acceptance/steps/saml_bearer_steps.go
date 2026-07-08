package steps

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/cucumber/godog"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// registerSAMLBearerSteps wires the RFC 7522 (ADR-0026 in
// identity-platform-go's auth-server) steps: registering a client that
// trusts a freshly-generated SAML issuer, and presenting a real signed
// assertion at /oauth/token — mirroring how PKCE scenarios generate their
// own code_verifier/code_challenge rather than depending on a fixture.
func registerSAMLBearerSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^a registered confidential OAuth client with scopes "([^"]*)" and grant type "urn:ietf:params:oauth:grant-type:saml2-bearer" trusting a generated SAML issuer$`,
		func(ctx context.Context, scopes string) error {
			return stepRegisterSAMLBearerClient(ctx, world(), scopes, true)
		})

	sctx.Step(`^a registered confidential OAuth client with scopes "([^"]*)" and grant type "urn:ietf:params:oauth:grant-type:saml2-bearer" with no trusted SAML issuer$`,
		func(ctx context.Context, scopes string) error {
			return stepRegisterSAMLBearerClient(ctx, world(), scopes, false)
		})

	sctx.Step(`^the client requests a token using the saml2-bearer grant with subject "([^"]*)"$`,
		func(ctx context.Context, subject string) error {
			w := world()
			htu := w.Services["auth-server"].BaseURL + "/oauth/token"
			return stepRequestSAMLBearerToken(ctx, w, subject, htu, htu)
		})

	sctx.Step(`^the client requests a token using the saml2-bearer grant with subject "([^"]*)" and audience "([^"]*)"$`,
		func(ctx context.Context, subject, audience string) error {
			w := world()
			htu := w.Services["auth-server"].BaseURL + "/oauth/token"
			return stepRequestSAMLBearerToken(ctx, w, subject, audience, htu)
		})
}

// samlBearerKeyStore implements dsig.X509KeyStore with a caller-supplied
// key/cert pair — goxmldsig's own MemoryX509KeyStore has no exported
// constructor.
type samlBearerKeyStore struct {
	key  *rsa.PrivateKey
	cert []byte // DER
}

func (k samlBearerKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return k.key, k.cert, nil
}

// generateSAMLBearerIssuer generates a fresh RSA key + self-signed
// certificate for one scenario's test IdP. Extracted from
// stepRegisterSAMLBearerClient to keep its cyclomatic complexity in budget.
func generateSAMLBearerIssuer() (certPEM, keyPEM string, certDER []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, fmt.Errorf("generating RSA key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "acceptance-test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, fmt.Errorf("creating self-signed cert: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM, certDER, nil
}

// stepRegisterSAMLBearerClient generates a fresh RSA key + self-signed
// certificate and stashes the signing key (PEM) in world.Vars for the
// later "When" step to sign an assertion with, regardless of trust — the
// client's own signing key is independent of what the server is
// configured to trust. When registerCert is false, the client is
// registered WITHOUT trusted_issuer_cert (for the "no trust established"
// negative scenario) — the assertion the later step signs is still
// well-formed and validly signed, but auth-server has nothing to verify
// it against.
func stepRegisterSAMLBearerClient(ctx context.Context, world *support.World, scopesStr string, registerCert bool) error {
	certPEM, keyPEM, certDER, err := generateSAMLBearerIssuer()
	if err != nil {
		return err
	}

	clientID, clientSecret, err := createSAMLBearerClient(ctx, world, scopesStr, certPEM, registerCert)
	if err != nil {
		return err
	}

	world.Vars["client_id"] = clientID
	world.Vars["client_secret"] = clientSecret
	world.Vars["saml_signing_key_pem"] = keyPEM
	world.Vars["saml_signing_cert_der_b64"] = base64.StdEncoding.EncodeToString(certDER)
	return nil
}

// createSAMLBearerClient posts to client-registry-service's POST /clients,
// including trusted_issuer_cert only when registerCert is true. Extracted
// from stepRegisterSAMLBearerClient to keep its cyclomatic complexity in
// budget.
func createSAMLBearerClient(ctx context.Context, world *support.World, scopesStr, certPEM string, registerCert bool) (clientID, clientSecret string, err error) {
	body := map[string]any{
		"name":        support.RandomID("acceptance-saml-client"),
		"client_type": "confidential",
		"scopes":      strings.Fields(scopesStr),
		"grant_types": []string{"urn:ietf:params:oauth:grant-type:saml2-bearer"},
	}
	if registerCert {
		body["trusted_issuer_cert"] = certPEM
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("marshalling create-client request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["client-registry-service"].BaseURL+"/clients", strings.NewReader(string(payload)))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("calling client-registry-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var created struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", "", fmt.Errorf("decoding create-client response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("create-client: want 201, got %d", resp.StatusCode)
	}
	return created.ClientID, created.ClientSecret, nil
}

// signStashedSAMLAssertion builds and signs a fresh SAML assertion (Subject
// NameID = subject, AudienceRestriction + bearer
// SubjectConfirmationData.Recipient = audience/htu respectively) using the
// key stashed by stepRegisterSAMLBearerClient, returning the serialized
// signed XML. Extracted from stepRequestSAMLBearerToken to keep its
// cyclomatic complexity in budget.
func signStashedSAMLAssertion(world *support.World, subject, audience, htu string) ([]byte, error) {
	block, _ := pem.Decode([]byte(world.Vars["saml_signing_key_pem"]))
	if block == nil {
		return nil, fmt.Errorf("no saml signing key stashed on world — did the registration step run?")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing stashed signing key: %w", err)
	}
	certDER, err := base64.StdEncoding.DecodeString(world.Vars["saml_signing_cert_der_b64"])
	if err != nil {
		return nil, fmt.Errorf("decoding stashed signing cert: %w", err)
	}

	now := time.Now()
	assertion := &saml.Assertion{
		ID:           support.RandomID("saml-assertion"),
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       saml.Issuer{Value: "https://idp.example.com"},
		Conditions: &saml.Conditions{
			NotBefore:    now.Add(-time.Minute),
			NotOnOrAfter: now.Add(time.Minute),
			AudienceRestrictions: []saml.AudienceRestriction{
				{Audience: saml.Audience{Value: audience}},
			},
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: subject},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						Recipient:    htu,
						NotOnOrAfter: now.Add(time.Minute),
					},
				},
			},
		},
	}

	signingCtx := dsig.NewDefaultSigningContext(samlBearerKeyStore{key: key, cert: certDER})
	signedEl, err := signingCtx.SignEnveloped(assertion.Element())
	if err != nil {
		return nil, fmt.Errorf("signing assertion: %w", err)
	}
	xmlBytes, err := etree.NewDocumentWithRoot(signedEl).WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serializing signed assertion: %w", err)
	}
	return xmlBytes, nil
}

// stepRequestSAMLBearerToken signs a fresh assertion (via
// signStashedSAMLAssertion) and posts it to auth-server's /oauth/token as
// the base64url-encoded assertion parameter. htu is always the real token
// endpoint URL — audience is varied independently so the wrong-audience
// negative scenario can diverge from it.
func stepRequestSAMLBearerToken(ctx context.Context, world *support.World, subject, audience, htu string) error {
	xmlBytes, err := signStashedSAMLAssertion(world, subject, audience, htu)
	if err != nil {
		return err
	}

	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:saml2-bearer"},
		"client_id":     {world.Vars["client_id"]},
		"client_secret": {world.Vars["client_secret"]},
		"assertion":     {base64.RawURLEncoding.EncodeToString(xmlBytes)},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["auth-server"].BaseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling auth-server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading auth-server response body: %w", err)
	}
	world.LastResponse = resp
	world.LastBody = respBody
	return nil
}
