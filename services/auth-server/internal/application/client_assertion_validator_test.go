package application_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

const testTokenEndpointIssuer = "https://auth.example.com"

// fakeClientLookup implements ports.ClientLookup for testing.
type fakeClientLookup struct {
	clients map[string]*domain.Client
}

func newFakeClientLookup() *fakeClientLookup {
	return &fakeClientLookup{clients: make(map[string]*domain.Client)}
}

func (f *fakeClientLookup) Lookup(_ context.Context, clientID string) (*domain.Client, error) {
	c, ok := f.clients[clientID]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "client not found")
	}
	return c, nil
}

// fakeJWKSFetcher implements ports.ClientJWKSFetcher, resolving kid ->
// public key from an in-memory map regardless of jwksURI, so tests can
// mint a key pair and register it without running an HTTP server.
type fakeJWKSFetcher struct {
	keys map[string]*rsa.PublicKey
	err  error
}

func newFakeJWKSFetcher() *fakeJWKSFetcher {
	return &fakeJWKSFetcher{keys: make(map[string]*rsa.PublicKey)}
}

func (f *fakeJWKSFetcher) FetchKey(_ context.Context, _, kid string) (*rsa.PublicKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	pub, ok := f.keys[kid]
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return pub, nil
}

// fakeReplayRepo implements domain.ClientAssertionReplayRepository.
type fakeReplayRepo struct {
	used map[string]bool
	err  error
}

func newFakeReplayRepo() *fakeReplayRepo {
	return &fakeReplayRepo{used: make(map[string]bool)}
}

func (f *fakeReplayRepo) MarkUsed(_ context.Context, jti string, _ time.Time) error {
	if f.err != nil {
		return f.err
	}
	if f.used[jti] {
		return domain.ErrClientAssertionReplayed
	}
	f.used[jti] = true
	return nil
}

// signAssertion builds and signs a JWT-bearer client assertion with the
// given claims and kid header, returning the raw token.
func signAssertion(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.RegisteredClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing assertion: %v", err)
	}
	return raw
}

func newAssertionTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func validAssertionClaims(clientID string) jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{testTokenEndpointIssuer},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        "jti-" + clientID,
	}
}

func newAssertionValidator(lookup *fakeClientLookup, fetcher *fakeJWKSFetcher, replay *fakeReplayRepo) *application.ClientAssertionValidator {
	return application.NewClientAssertionValidator(lookup, fetcher, replay, testTokenEndpointIssuer)
}

func TestClientAssertionValidator_Authenticate_Success(t *testing.T) {
	// Arrange
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	replay := newFakeReplayRepo()
	v := newAssertionValidator(lookup, fetcher, replay)
	assertion := signAssertion(t, priv, "kid-1", validAssertionClaims("jwt-client"))

	// Act
	client, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if client.ID != "jwt-client" {
		t.Errorf("client.ID = %q", client.ID)
	}
}

func TestClientAssertionValidator_Authenticate_ClientNotRegisteredForJWKS(t *testing.T) {
	// Arrange — client exists but has no jwks_uri (never opted in).
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["secret-only-client"] = &domain.Client{ID: "secret-only-client"}
	fetcher := newFakeJWKSFetcher()
	v := newAssertionValidator(lookup, fetcher, newFakeReplayRepo())
	assertion := signAssertion(t, priv, "kid-1", validAssertionClaims("secret-only-client"))

	// Act
	_, err := v.Authenticate(context.Background(), "secret-only-client", assertion)

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want ErrCodeUnauthorized", err)
	}
}

func TestClientAssertionValidator_Authenticate_UnknownClient(t *testing.T) {
	// Arrange
	priv := newAssertionTestRSAKey(t)
	v := newAssertionValidator(newFakeClientLookup(), newFakeJWKSFetcher(), newFakeReplayRepo())
	assertion := signAssertion(t, priv, "kid-1", validAssertionClaims("never-registered"))

	// Act
	_, err := v.Authenticate(context.Background(), "never-registered", assertion)

	// Assert
	if err == nil {
		t.Fatal("expected error for unknown client")
	}
}

func TestClientAssertionValidator_Authenticate_WrongSigningKey(t *testing.T) {
	// Arrange — assertion signed by a key that is NOT the one FetchKey
	// resolves for this kid; signature verification must fail.
	signingKey := newAssertionTestRSAKey(t)
	registeredKey := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &registeredKey.PublicKey
	v := newAssertionValidator(lookup, fetcher, newFakeReplayRepo())
	assertion := signAssertion(t, signingKey, "kid-1", validAssertionClaims("jwt-client"))

	// Act
	_, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if err == nil {
		t.Fatal("expected error for signature mismatch")
	}
}

func TestClientAssertionValidator_Authenticate_IssuerMismatch(t *testing.T) {
	// Arrange — assertion's iss does not match the supplied client_id.
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	v := newAssertionValidator(lookup, fetcher, newFakeReplayRepo())
	claims := validAssertionClaims("jwt-client")
	claims.Issuer = "someone-else"
	assertion := signAssertion(t, priv, "kid-1", claims)

	// Act
	_, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want ErrCodeUnauthorized", err)
	}
}

func TestClientAssertionValidator_Authenticate_SubjectMismatch(t *testing.T) {
	// Arrange
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	v := newAssertionValidator(lookup, fetcher, newFakeReplayRepo())
	claims := validAssertionClaims("jwt-client")
	claims.Subject = "someone-else"
	assertion := signAssertion(t, priv, "kid-1", claims)

	// Act
	_, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want ErrCodeUnauthorized", err)
	}
}

func TestClientAssertionValidator_Authenticate_WrongAudience(t *testing.T) {
	// Arrange
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	v := newAssertionValidator(lookup, fetcher, newFakeReplayRepo())
	claims := validAssertionClaims("jwt-client")
	claims.Audience = jwt.ClaimStrings{"https://someone-else.example.com"}
	assertion := signAssertion(t, priv, "kid-1", claims)

	// Act
	_, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want ErrCodeUnauthorized", err)
	}
}

func TestClientAssertionValidator_Authenticate_ExpiredAssertion(t *testing.T) {
	// Arrange
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	v := newAssertionValidator(lookup, fetcher, newFakeReplayRepo())
	claims := validAssertionClaims("jwt-client")
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
	assertion := signAssertion(t, priv, "kid-1", claims)

	// Act
	_, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if err == nil {
		t.Fatal("expected error for expired assertion")
	}
}

func TestClientAssertionValidator_Authenticate_MissingJTI(t *testing.T) {
	// Arrange
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	v := newAssertionValidator(lookup, fetcher, newFakeReplayRepo())
	claims := validAssertionClaims("jwt-client")
	claims.ID = ""
	assertion := signAssertion(t, priv, "kid-1", claims)

	// Act
	_, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want ErrCodeUnauthorized", err)
	}
}

func TestClientAssertionValidator_Authenticate_ReplayedJTIRejected(t *testing.T) {
	// Arrange — same assertion presented twice; the second call must fail.
	priv := newAssertionTestRSAKey(t)
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	fetcher := newFakeJWKSFetcher()
	fetcher.keys["kid-1"] = &priv.PublicKey
	replay := newFakeReplayRepo()
	v := newAssertionValidator(lookup, fetcher, replay)
	assertion := signAssertion(t, priv, "kid-1", validAssertionClaims("jwt-client"))
	if _, err := v.Authenticate(context.Background(), "jwt-client", assertion); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	// Act
	_, err := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want ErrCodeUnauthorized", err)
	}
}

func TestClientAssertionValidator_Authenticate_UnsupportedAlgorithmRejected(t *testing.T) {
	// Arrange — HS256-signed assertion must be rejected outright (RFC 8725
	// §3.1 algorithm-confusion defense); this platform only accepts RS256
	// client assertions.
	lookup := newFakeClientLookup()
	lookup.clients["jwt-client"] = &domain.Client{ID: "jwt-client", JWKSURI: "https://client.example.com/jwks.json"}
	v := newAssertionValidator(lookup, newFakeJWKSFetcher(), newFakeReplayRepo())
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, validAssertionClaims("jwt-client"))
	assertion, err := token.SignedString([]byte("any-hmac-secret-value-here"))
	if err != nil {
		t.Fatalf("signing HS256 assertion: %v", err)
	}

	// Act
	_, aerr := v.Authenticate(context.Background(), "jwt-client", assertion)

	// Assert
	if aerr == nil {
		t.Fatal("expected error for non-RS256 assertion")
	}
}
