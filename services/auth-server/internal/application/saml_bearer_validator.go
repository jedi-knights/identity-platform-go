package application

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// samlBearerConfirmationMethod is the RFC 7522 §3 required SubjectConfirmation
// method — bearer confirmation, not holder-of-key.
const samlBearerConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

// samlAssertionElementTag/NS pin the expected top-level element so a request
// body wrapping the assertion in something else (e.g. a <samlp:Response>
// carrying multiple <Assertion> children — the shape CVE-2022-41912 exploited
// in crewjam/saml itself) is rejected before signature verification even
// runs, rather than relying on looking only at the first Assertion found.
const (
	samlAssertionElementTag = "Assertion"
	samlAssertionNS         = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// ValidatedSAMLAssertion is the plain-data result of a successful validation.
// domain has no external imports (this repo's architecture rule), so this
// type intentionally carries no crewjam/saml or goxmldsig types — only the
// two claims the grant strategy actually needs.
type ValidatedSAMLAssertion struct {
	// Subject is the assertion's NameID value — the resource owner the
	// issued token represents.
	Subject string
	// Issuer is recorded for audit only; trust was already established via
	// the client's registered TrustedIssuerCert, not this string.
	Issuer string
}

// SAMLBearerValidator validates RFC 7522 §3 SAML bearer assertions
// (ADR-0026). crewjam/saml has no exported entrypoint for validating a bare
// assertion outside a full SSO Response envelope, so this reuses its
// schema.go types purely as encoding/xml unmarshal targets and calls
// goxmldsig directly for signature verification — see the ADR for why, and
// for the required goxmldsig >= 1.6.0 override (CVE-2026-33487).
type SAMLBearerValidator struct{}

// NewSAMLBearerValidator constructs a SAMLBearerValidator. Stateless — safe
// to share across requests.
func NewSAMLBearerValidator() *SAMLBearerValidator {
	return &SAMLBearerValidator{}
}

// Validate parses rawXML, verifies its signature against trustedCertPEM,
// and checks Conditions/SubjectConfirmation against audience (this
// authorization server's token endpoint URL, used as both the required
// AudienceRestriction and the required bearer SubjectConfirmationData
// Recipient per RFC 7522 §3).
func (v *SAMLBearerValidator) Validate(rawXML []byte, trustedCertPEM, audience string) (*ValidatedSAMLAssertion, error) {
	trustedCert, err := parseTrustedIssuerCert(trustedCertPEM)
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}

	el, assertion, err := parseSAMLAssertion(rawXML)
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}

	if err := verifySAMLSignature(el, trustedCert); err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	if err := checkSAMLConditions(assertion.Conditions, audience); err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	if err := checkBearerSubjectConfirmation(assertion.Subject, audience); err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	subjectValue, err := nameIDValue(assertion.Subject)
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}

	return &ValidatedSAMLAssertion{Subject: subjectValue, Issuer: assertion.Issuer.Value}, nil
}

// nameIDValue extracts Subject.NameID.Value, erroring if either is absent.
// Extracted from Validate to keep its cyclomatic complexity in budget.
func nameIDValue(subject *saml.Subject) (string, error) {
	if subject == nil || subject.NameID == nil || subject.NameID.Value == "" {
		return "", errors.New("assertion missing subject NameID")
	}
	return subject.NameID.Value, nil
}

func parseTrustedIssuerCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("trusted issuer cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted issuer cert: %w", err)
	}
	return cert, nil
}

// parseSAMLAssertion parses rawXML once into both an etree.Element (for
// signature verification) and a saml.Assertion (for claims) — both views
// of the exact same bytes, so there is no risk of validating one element's
// signature while reading claims from a different one. Rejects any root
// element that isn't a single <saml:Assertion>.
func parseSAMLAssertion(rawXML []byte) (*etree.Element, *saml.Assertion, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawXML); err != nil {
		return nil, nil, fmt.Errorf("parsing assertion xml: %w", err)
	}
	el := doc.Root()
	if el == nil {
		return nil, nil, errors.New("empty assertion document")
	}
	if el.Tag != samlAssertionElementTag || el.NamespaceURI() != samlAssertionNS {
		return nil, nil, fmt.Errorf("expected a top-level %s element, got %q", samlAssertionElementTag, el.FullTag())
	}

	var assertion saml.Assertion
	if err := xml.Unmarshal(rawXML, &assertion); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling assertion: %w", err)
	}
	return el, &assertion, nil
}

// verifySAMLSignature mirrors crewjam/saml's own validateSignature: strip
// Signature/KeyInfo when it carries no embedded X509Certificate (forces
// goxmldsig to fall back to the trusted root), then validate the exact
// element the caller will read claims from. With a single trusted root
// (this platform's one-cert-per-client design), goxmldsig's own
// verifyCertificate already requires any embedded KeyInfo certificate to
// equal that root, so the strip is defense-in-depth rather than the only
// check — see ADR-0026.
func verifySAMLSignature(el *etree.Element, trustedCert *x509.Certificate) error {
	if el.FindElement("./Signature") == nil {
		return errors.New("assertion is not signed")
	}
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		if sigEl := el.FindElement("./Signature"); sigEl != nil {
			if keyInfo := sigEl.FindElement("KeyInfo"); keyInfo != nil {
				sigEl.RemoveChild(keyInfo)
			}
		}
	}

	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{trustedCert}}
	validationContext := dsig.NewDefaultValidationContext(store)
	validationContext.IdAttribute = "ID"
	if _, err := validationContext.Validate(el); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func checkSAMLConditions(cond *saml.Conditions, audience string) error {
	if cond == nil {
		return errors.New("assertion missing Conditions")
	}
	now := time.Now()
	if !cond.NotBefore.IsZero() && now.Before(cond.NotBefore) {
		return errors.New("assertion not yet valid (Conditions.NotBefore)")
	}
	if !cond.NotOnOrAfter.IsZero() && !now.Before(cond.NotOnOrAfter) {
		return errors.New("assertion expired (Conditions.NotOnOrAfter)")
	}
	if !audienceRestricted(cond.AudienceRestrictions, audience) {
		return fmt.Errorf("assertion AudienceRestriction does not include %q", audience)
	}
	return nil
}

// audienceRestricted reports whether restrictions contains audience.
// Extracted from checkSAMLConditions to keep its cyclomatic complexity in
// budget.
func audienceRestricted(restrictions []saml.AudienceRestriction, audience string) bool {
	for _, ar := range restrictions {
		if ar.Audience.Value == audience {
			return true
		}
	}
	return false
}

// checkBearerSubjectConfirmation requires at least one bearer-method
// SubjectConfirmation whose Recipient matches recipient and whose validity
// window (if present) covers now — per RFC 7522 §3's bearer confirmation
// requirements.
func checkBearerSubjectConfirmation(subject *saml.Subject, recipient string) error {
	if subject == nil {
		return errors.New("assertion missing Subject")
	}
	now := time.Now()
	for _, sc := range subject.SubjectConfirmations {
		if isValidBearerConfirmation(sc, recipient, now) {
			return nil
		}
	}
	return errors.New("assertion has no valid bearer SubjectConfirmation for this recipient")
}

// isValidBearerConfirmation reports whether sc is a bearer-method
// confirmation targeting recipient and currently within its validity
// window. Extracted from checkBearerSubjectConfirmation to keep its
// cyclomatic complexity in budget.
func isValidBearerConfirmation(sc saml.SubjectConfirmation, recipient string, now time.Time) bool {
	if sc.Method != samlBearerConfirmationMethod || sc.SubjectConfirmationData == nil {
		return false
	}
	data := sc.SubjectConfirmationData
	return data.Recipient == recipient && withinWindow(data.NotBefore, data.NotOnOrAfter, now)
}

// withinWindow reports whether now falls within [notBefore, notOnOrAfter),
// treating a zero time.Time bound as absent (RFC 7522's wire format may
// omit either).
func withinWindow(notBefore, notOnOrAfter, now time.Time) bool {
	if !notOnOrAfter.IsZero() && !now.Before(notOnOrAfter) {
		return false
	}
	if !notBefore.IsZero() && now.Before(notBefore) {
		return false
	}
	return true
}
