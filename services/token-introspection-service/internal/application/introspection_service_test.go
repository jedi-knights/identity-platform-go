//go:build unit

package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

// fakeValidator implements domain.TokenValidator for testing.
type fakeValidator struct {
	result *domain.IntrospectionResult
	err    error
}

func (f *fakeValidator) Validate(_ context.Context, _ string) (*domain.IntrospectionResult, error) {
	return f.result, f.err
}

// fakeRevocation implements domain.RevocationChecker for testing.
type fakeRevocation struct {
	active bool
	err    error
}

func (f *fakeRevocation) IsActive(_ context.Context, _ string) (bool, error) {
	return f.active, f.err
}

func TestIntrospectionService_Introspect(t *testing.T) {
	activeResult := &domain.IntrospectionResult{Active: true, Subject: "user-123", Scope: "read"}
	inactiveResult := &domain.IntrospectionResult{Active: false}

	cases := []struct {
		name       string
		validator  domain.TokenValidator
		revocation domain.RevocationChecker
		raw        string
		wantActive bool
		wantErr    bool
	}{
		{
			name:       "valid token with no revocation checker returns active",
			validator:  &fakeValidator{result: activeResult},
			revocation: nil,
			raw:        "some.jwt.token",
			wantActive: true,
		},
		{
			name:       "invalid token with no revocation checker returns inactive",
			validator:  &fakeValidator{result: inactiveResult},
			revocation: nil,
			raw:        "invalid.jwt.token",
			wantActive: false,
		},
		{
			name:       "valid token present in revocation store returns active",
			validator:  &fakeValidator{result: activeResult},
			revocation: &fakeRevocation{active: true},
			raw:        "some.jwt.token",
			wantActive: true,
		},
		{
			name:       "valid token revoked in store returns inactive",
			validator:  &fakeValidator{result: activeResult},
			revocation: &fakeRevocation{active: false},
			raw:        "revoked.jwt.token",
			wantActive: false,
		},
		{
			name:       "invalid token skips revocation check and returns inactive",
			validator:  &fakeValidator{result: inactiveResult},
			revocation: &fakeRevocation{active: true}, // would say active, but validator says inactive first
			raw:        "invalid.jwt.token",
			wantActive: false,
		},
		{
			// The service propagates revocation store errors so the handler can log them
			// with trace ID context. The handler translates the error to {active:false}.
			name:       "revocation store error propagates to caller",
			validator:  &fakeValidator{result: activeResult},
			revocation: &fakeRevocation{err: errors.New("redis connection failed")},
			raw:        "some.jwt.token",
			wantErr:    true,
		},
		{
			name:      "validator error propagates",
			validator: &fakeValidator{err: errors.New("unexpected validator error")},
			raw:       "some.jwt.token",
			wantErr:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := application.NewIntrospectionService(tc.validator, tc.revocation)
			result, err := svc.Introspect(context.Background(), tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Active != tc.wantActive {
				t.Errorf("Active = %v, want %v", result.Active, tc.wantActive)
			}
		})
	}
}
