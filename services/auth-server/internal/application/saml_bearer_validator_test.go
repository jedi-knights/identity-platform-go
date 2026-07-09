package application_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
)

const testRecipient = "https://auth.example.com/oauth/token"

// testKeyStore implements dsig.X509KeyStore with a caller-supplied key/cert
// pair — goxmldsig's own MemoryX509KeyStore has no exported constructor, so
// tests that need to control both the signing key AND the resulting trusted
// certificate (to register as TrustedIssuerCert) implement the tiny
// interface directly instead.
type testKeyStore struct {
	key  *rsa.PrivateKey
	cert []byte // DER
}

func (k testKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return k.key, k.cert, nil
}

// generateTestIssuer creates a fresh RSA key + self-signed certificate,
// returning the key store (for signing) and the cert PEM (for registering
// as a client's TrustedIssuerCert).
func generateTestIssuer(t *testing.T) (testKeyStore, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating self-signed cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return testKeyStore{key: key, cert: certDER}, certPEM
}

// assertionOpts lets each test mutate exactly one field of an otherwise
// valid assertion before signing.
type assertionOpts struct {
	subjectValue        string
	audience            string
	recipient           string
	confirmationMethod  string
	notBefore           time.Time
	notOnOrAfter        time.Time
	confirmNotOnOrAfter time.Time
	omitSignature       bool
	skipSubjectConfirm  bool
}

func defaultAssertionOpts() assertionOpts {
	now := time.Now()
	return assertionOpts{
		subjectValue:        "saml-user-1",
		audience:            testRecipient,
		recipient:           testRecipient,
		confirmationMethod:  "urn:oasis:names:tc:SAML:2.0:cm:bearer",
		notBefore:           now.Add(-time.Minute),
		notOnOrAfter:        now.Add(time.Minute),
		confirmNotOnOrAfter: now.Add(time.Minute),
	}
}

// signTestAssertion builds a saml.Assertion per opts, signs it with ks, and
// returns the serialized XML bytes.
func signTestAssertion(t *testing.T, ks testKeyStore, opts assertionOpts) []byte {
	t.Helper()
	assertion := &saml.Assertion{
		ID:           "test-assertion-" + t.Name(),
		IssueInstant: time.Now(),
		Version:      "2.0",
		Issuer:       saml.Issuer{Value: "https://idp.example.com"},
		Conditions: &saml.Conditions{
			NotBefore:    opts.notBefore,
			NotOnOrAfter: opts.notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{
				{Audience: saml.Audience{Value: opts.audience}},
			},
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: opts.subjectValue},
		},
	}
	if !opts.skipSubjectConfirm {
		assertion.Subject.SubjectConfirmations = []saml.SubjectConfirmation{
			{
				Method: opts.confirmationMethod,
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					Recipient:    opts.recipient,
					NotOnOrAfter: opts.confirmNotOnOrAfter,
				},
			},
		}
	}

	el := assertion.Element()
	if opts.omitSignature {
		doc := etree.NewDocumentWithRoot(el)
		xmlBytes, err := doc.WriteToBytes()
		if err != nil {
			t.Fatalf("serializing unsigned assertion: %v", err)
		}
		return xmlBytes
	}

	signingCtx := dsig.NewDefaultSigningContext(ks)
	signedEl, err := signingCtx.SignEnveloped(el)
	if err != nil {
		t.Fatalf("signing assertion: %v", err)
	}
	doc := etree.NewDocumentWithRoot(signedEl)
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serializing signed assertion: %v", err)
	}
	return xmlBytes
}

func TestSAMLBearerValidator_Validate_ValidAssertion_ReturnsSubjectAndIssuer(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	xmlBytes := signTestAssertion(t, ks, defaultAssertionOpts())
	v := application.NewSAMLBearerValidator()

	// Act
	got, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Subject != "saml-user-1" {
		t.Errorf("Subject = %q, want %q", got.Subject, "saml-user-1")
	}
	if got.Issuer != "https://idp.example.com" {
		t.Errorf("Issuer = %q, want %q", got.Issuer, "https://idp.example.com")
	}
}

func TestSAMLBearerValidator_Validate_TamperedAssertion_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	xmlBytes := signTestAssertion(t, ks, defaultAssertionOpts())
	tampered := []byte(string(xmlBytes[:len(xmlBytes)-20]) + "tampered-suffix-xyz>")
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(tampered, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a tampered assertion")
	}
}

func TestSAMLBearerValidator_Validate_UnsignedAssertion_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.omitSignature = true
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for an unsigned assertion")
	}
}

func TestSAMLBearerValidator_Validate_UntrustedSigner_ReturnsError(t *testing.T) {
	// Arrange — signed by a DIFFERENT key than the one whose cert is trusted.
	signerKS, _ := generateTestIssuer(t)
	_, trustedCertPEM := generateTestIssuer(t)
	xmlBytes := signTestAssertion(t, signerKS, defaultAssertionOpts())
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, trustedCertPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for an assertion signed by an untrusted key")
	}
}

func TestSAMLBearerValidator_Validate_ExpiredConditions_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.notBefore = time.Now().Add(-time.Hour)
	opts.notOnOrAfter = time.Now().Add(-time.Minute) // already expired
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for expired Conditions")
	}
}

func TestSAMLBearerValidator_Validate_NotYetValidConditions_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.notBefore = time.Now().Add(time.Hour) // not valid yet
	opts.notOnOrAfter = time.Now().Add(2 * time.Hour)
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for not-yet-valid Conditions")
	}
}

func TestSAMLBearerValidator_Validate_WrongAudience_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.audience = "https://someone-else.example.com/oauth/token"
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a mismatched AudienceRestriction")
	}
}

func TestSAMLBearerValidator_Validate_WrongRecipient_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.recipient = "https://someone-else.example.com/oauth/token"
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for a mismatched SubjectConfirmationData.Recipient")
	}
}

func TestSAMLBearerValidator_Validate_NonBearerConfirmationMethod_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.confirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error when no bearer SubjectConfirmation is present")
	}
}

func TestSAMLBearerValidator_Validate_ExpiredSubjectConfirmation_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.confirmNotOnOrAfter = time.Now().Add(-time.Minute)
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for an expired bearer SubjectConfirmationData")
	}
}

func TestSAMLBearerValidator_Validate_MissingSubjectConfirmation_ReturnsError(t *testing.T) {
	// Arrange
	ks, certPEM := generateTestIssuer(t)
	opts := defaultAssertionOpts()
	opts.skipSubjectConfirm = true
	xmlBytes := signTestAssertion(t, ks, opts)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error when Subject has no SubjectConfirmation at all")
	}
}

func TestSAMLBearerValidator_Validate_MalformedXML_ReturnsError(t *testing.T) {
	// Arrange
	_, certPEM := generateTestIssuer(t)
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate([]byte("not xml at all"), certPEM, testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for malformed XML")
	}
}

func TestSAMLBearerValidator_Validate_InvalidTrustedCertPEM_ReturnsError(t *testing.T) {
	// Arrange
	ks, _ := generateTestIssuer(t)
	xmlBytes := signTestAssertion(t, ks, defaultAssertionOpts())
	v := application.NewSAMLBearerValidator()

	// Act
	_, err := v.Validate(xmlBytes, "not a pem certificate", testRecipient)

	// Assert
	if err == nil {
		t.Fatal("expected an error for an invalid trusted-cert PEM")
	}
}
