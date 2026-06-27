//go:build unit

package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jedi-knights/go-platform/audit"

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

// --- Audit emission (ADR-0018 / ADR-0019) ---

type captureSink struct {
	events []audit.Event
	err    error
}

func (c *captureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

var errAuditFailure = errors.New("simulated audit transport failure")

func TestIntrospect_EmitsForActiveToken(t *testing.T) {
	validator := &fakeValidator{result: &domain.IntrospectionResult{
		Active:   true,
		Subject:  "u-1",
		ClientID: "c-1",
		JTI:      "jti-xyz",
	}}
	sink := &captureSink{}
	svc := application.NewIntrospectionService(validator, nil).
		WithAudit(audit.New(sink), "token-introspection-service")

	if _, err := svc.Introspect(context.Background(), "any.jwt"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.EventType != "token_introspected" {
		t.Errorf("event_type = %q, want token_introspected", e.EventType)
	}
	if e.ActorID != "bearer-introspection-caller" {
		t.Errorf("actor_id = %q, want bearer-introspection-caller", e.ActorID)
	}
	if e.SubjectID != "u-1" {
		t.Errorf("subject_id = %q, want u-1", e.SubjectID)
	}
	if e.ResourcePath != "token-introspection-service/token/access" {
		t.Errorf("resource_path = %q, want token-introspection-service/token/access", e.ResourcePath)
	}
	if active, _ := e.Attrs["active"].(bool); !active {
		t.Errorf("attrs.active = %v, want true", e.Attrs["active"])
	}
}

func TestIntrospect_EmitsForInactiveResult(t *testing.T) {
	validator := &fakeValidator{result: &domain.IntrospectionResult{Active: false}}
	sink := &captureSink{}
	svc := application.NewIntrospectionService(validator, nil).
		WithAudit(audit.New(sink), "token-introspection-service")

	if _, err := svc.Introspect(context.Background(), "expired.jwt"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	if active, _ := sink.events[0].Attrs["active"].(bool); active {
		t.Errorf("attrs.active = %v, want false", sink.events[0].Attrs["active"])
	}
}

func TestIntrospect_EmitsForRevokedToken(t *testing.T) {
	validator := &fakeValidator{result: &domain.IntrospectionResult{
		Active:   true,
		Subject:  "u-1",
		ClientID: "c-1",
	}}
	revocation := &fakeRevocation{active: false}
	sink := &captureSink{}
	svc := application.NewIntrospectionService(validator, revocation).
		WithAudit(audit.New(sink), "token-introspection-service")

	res, err := svc.Introspect(context.Background(), "revoked.jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Active {
		t.Errorf("expected revoked token inactive")
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	if active, _ := sink.events[0].Attrs["active"].(bool); active {
		t.Errorf("attrs.active = %v, want false on revoked token", sink.events[0].Attrs["active"])
	}
}

func TestIntrospect_AuditFailureSurfaces(t *testing.T) {
	validator := &fakeValidator{result: &domain.IntrospectionResult{Active: true, Subject: "u-1"}}
	sink := &captureSink{err: errAuditFailure}
	svc := application.NewIntrospectionService(validator, nil).
		WithAudit(audit.New(sink), "token-introspection-service")

	_, err := svc.Introspect(context.Background(), "any.jwt")
	if err == nil {
		t.Fatal("expected error when audit emit fails")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestIntrospect_ValidatorErrorBypassesAudit(t *testing.T) {
	// A validator infrastructure error is propagated directly so the
	// handler can translate it to RFC 7662 §2.2 safe inactive without
	// ambiguity about which error originated where.
	validatorErr := errors.New("validator infrastructure failure")
	validator := &fakeValidator{err: validatorErr}
	sink := &captureSink{}
	svc := application.NewIntrospectionService(validator, nil).
		WithAudit(audit.New(sink), "token-introspection-service")

	if _, err := svc.Introspect(context.Background(), "any.jwt"); !errors.Is(err, validatorErr) {
		t.Errorf("expected validator error, got %v", err)
	}
	if len(sink.events) != 0 {
		t.Errorf("expected no audit event when validator fails, got %d", len(sink.events))
	}
}

func TestIntrospectionService_WithAudit_NilEmitterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = application.NewIntrospectionService(&fakeValidator{}, nil).
		WithAudit(nil, "token-introspection-service")
}
