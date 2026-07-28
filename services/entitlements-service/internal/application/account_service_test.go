package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
)

type captureSink struct {
	events []audit.Event
	err    error
}

func (c *captureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

var errAuditFailure = errors.New("simulated audit transport failure")

func newSvc() (*application.AccountService, *captureSink) {
	repo := memory.NewAccountRepository()
	sink := &captureSink{}
	svc := application.NewAccountService(repo).
		WithAudit(audit.New(sink), "entitlements-service")
	return svc, sink
}

func TestCreatePersonalAccount_ReturnsAccountID(t *testing.T) {
	// Arrange
	svc, _ := newSvc()

	// Act
	acc, _, err := svc.CreatePersonalAccount(context.Background(), "user-1", "u1@example.com")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acc.ID == "" {
		t.Error("expected non-empty account ID")
	}
}

func TestCreatePersonalAccount_IsIdempotent(t *testing.T) {
	// Arrange
	svc, _ := newSvc()

	// Act
	first, _, _ := svc.CreatePersonalAccount(context.Background(), "user-1", "u1@example.com")
	second, _, _ := svc.CreatePersonalAccount(context.Background(), "user-1", "u1@example.com")

	// Assert
	if first.ID != second.ID {
		t.Errorf("expected same ID across calls, got %q and %q", first.ID, second.ID)
	}
}

func TestCreatePersonalAccount_ValidationRejectsEmptyUserID(t *testing.T) {
	// Arrange
	svc, _ := newSvc()

	// Act
	_, _, err := svc.CreatePersonalAccount(context.Background(), "", "u@example.com")

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsBadRequest(err) {
		t.Errorf("expected bad-request error, got %v", err)
	}
}

func TestCreatePersonalAccount_ValidationRejectsEmptyEmail(t *testing.T) {
	// Arrange
	svc, _ := newSvc()

	// Act
	_, _, err := svc.CreatePersonalAccount(context.Background(), "user-1", "")

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsBadRequest(err) {
		t.Errorf("expected bad-request error, got %v", err)
	}
}

func TestCreatePersonalAccount_EmitsAccountCreated(t *testing.T) {
	// Arrange
	svc, sink := newSvc()

	// Act
	acc, _, err := svc.CreatePersonalAccount(context.Background(), "user-1", "u1@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EventType", e.EventType, "account_created"},
		{"Service", e.Service, "entitlements-service"},
		{"ActorType", string(e.ActorType), string(audit.ActorTypeUser)},
		{"ActorID", e.ActorID, "user-1"},
		{"SubjectID", e.SubjectID, acc.ID},
		{"ResourceKind", string(e.ResourceKind), string(audit.ResourceKindEndpoint)},
		{"ResourceID", e.ResourceID, "accounts.personal"},
		{"ResourcePath", e.ResourcePath, "entitlements-service/endpoint/accounts.personal"},
		{"Action", e.Action, "create"},
		{"Decision", string(e.Decision), string(audit.DecisionAllow)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("event.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
}

func TestCreatePersonalAccount_IdempotentDoesNotDoubleEmit(t *testing.T) {
	// Arrange
	svc, sink := newSvc()

	// Act — two calls with the same user_id must emit exactly one
	// account_created event (idempotent create means the second call is
	// a no-op, not a re-emit).
	_, _, _ = svc.CreatePersonalAccount(context.Background(), "user-1", "u1@example.com")
	_, _, _ = svc.CreatePersonalAccount(context.Background(), "user-1", "u1@example.com")

	// Assert
	if len(sink.events) != 1 {
		t.Errorf("expected 1 audit event across two idempotent calls, got %d", len(sink.events))
	}
}

func TestCreatePersonalAccount_AuditFailureSurfaces(t *testing.T) {
	// Arrange — durable-sink failures on paid events must fail the
	// request per ADR-0019. account_created is paid because it triggers
	// downstream Lago customer creation.
	repo := memory.NewAccountRepository()
	sink := &captureSink{err: errAuditFailure}
	svc := application.NewAccountService(repo).
		WithAudit(audit.New(sink), "entitlements-service")

	// Act
	_, _, err := svc.CreatePersonalAccount(context.Background(), "user-1", "u1@example.com")

	// Assert
	if err == nil {
		t.Fatal("expected error when audit emit fails")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestNewAccountService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil repo")
		}
	}()
	_ = application.NewAccountService(nil)
}

func TestWithAudit_NilEmitterPanics(t *testing.T) {
	repo := memory.NewAccountRepository()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = application.NewAccountService(repo).WithAudit(nil, "entitlements-service")
}
