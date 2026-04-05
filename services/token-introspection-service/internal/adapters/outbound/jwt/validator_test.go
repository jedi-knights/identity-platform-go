package jwt_test

import (
	"context"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	jwtadapter "github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/adapters/outbound/jwt"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

func makeToken(t *testing.T, key []byte, claims gojwt.MapClaims) string {
	t.Helper()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return raw
}

type validateCase struct {
	name        string
	token       func() string
	wantActive  bool
	wantSubject string
	wantScope   string
}

func assertValidateResult(t *testing.T, result *domain.IntrospectionResult, tc validateCase) {
	t.Helper()
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Active != tc.wantActive {
		t.Errorf("Active = %v, want %v", result.Active, tc.wantActive)
	}
	if tc.wantSubject != "" && result.Subject != tc.wantSubject {
		t.Errorf("Subject = %q, want %q", result.Subject, tc.wantSubject)
	}
	if tc.wantScope != "" && result.Scope != tc.wantScope {
		t.Errorf("Scope = %q, want %q", result.Scope, tc.wantScope)
	}
}

func TestValidator_Validate(t *testing.T) {
	signingKey := []byte("super-secret-key-for-testing-only-32+")

	cases := []validateCase{
		{
			name: "valid token returns active=true with claims",
			token: func() string {
				return makeToken(t, signingKey, gojwt.MapClaims{
					"sub":       "user-123",
					"client_id": "my-client",
					"scope":     "read write",
					"exp":       time.Now().Add(time.Hour).Unix(),
					"iat":       time.Now().Unix(),
					"iss":       "identity-platform",
				})
			},
			wantActive:  true,
			wantSubject: "user-123",
			wantScope:   "read write",
		},
		{
			name: "expired token returns active=false",
			token: func() string {
				return makeToken(t, signingKey, gojwt.MapClaims{
					"sub": "user-456",
					"exp": time.Now().Add(-time.Hour).Unix(),
				})
			},
			wantActive: false,
		},
		{
			name:       "malformed token returns active=false",
			token:      func() string { return "not.a.jwt" },
			wantActive: false,
		},
		{
			name: "wrong signing key returns active=false",
			token: func() string {
				return makeToken(t, []byte("wrong-key-entirely-different-32+"), gojwt.MapClaims{
					"sub": "user-789",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
			},
			wantActive: false,
		},
		{
			name:       "empty token returns active=false",
			token:      func() string { return "" },
			wantActive: false,
		},
	}

	v := jwtadapter.NewValidator(signingKey)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := v.Validate(context.Background(), tc.token())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertValidateResult(t, result, tc)
		})
	}
}
