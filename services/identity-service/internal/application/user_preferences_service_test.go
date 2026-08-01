package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/application"
)

// prefsCaptureSink is a minimal audit.Sink recording every event the
// service emits, so assertions can inspect emissions per test.
type prefsCaptureSink struct {
	events []audit.Event
	err    error
}

func (c *prefsCaptureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

func newPrefsServiceWithAudit(sink audit.Sink) *application.UserPreferencesService {
	return application.NewUserPreferencesService(memory.NewUserPreferencesRepository()).
		WithAudit(audit.New(sink), "identity-service")
}

func TestGetActiveAccount_MissingReturnsEmpty(t *testing.T) {
	svc := application.NewUserPreferencesService(memory.NewUserPreferencesRepository())

	got, err := svc.GetActiveAccount(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("Get on missing user: want empty, got %q", got)
	}
}

func TestGetActiveAccount_ReturnsStoredValue(t *testing.T) {
	sink := &prefsCaptureSink{}
	svc := newPrefsServiceWithAudit(sink)
	ctx := context.Background()

	if err := svc.SetActiveAccount(ctx, "u-1", "acc-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := svc.GetActiveAccount(ctx, "u-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "acc-1" {
		t.Fatalf("Get: want acc-1, got %q", got)
	}
}

func TestGetActiveAccount_RejectsEmptyUserID(t *testing.T) {
	svc := application.NewUserPreferencesService(memory.NewUserPreferencesRepository())

	_, err := svc.GetActiveAccount(context.Background(), "")
	if !apperrors.IsBadRequest(err) {
		t.Fatalf("want bad-request, got %v", err)
	}
}

func TestSetActiveAccount_RejectsEmptyUserID(t *testing.T) {
	svc := application.NewUserPreferencesService(memory.NewUserPreferencesRepository())

	err := svc.SetActiveAccount(context.Background(), "", "acc-1")
	if !apperrors.IsBadRequest(err) {
		t.Fatalf("want bad-request, got %v", err)
	}
}

func TestSetActiveAccount_RejectsEmptyAccountID(t *testing.T) {
	svc := application.NewUserPreferencesService(memory.NewUserPreferencesRepository())

	err := svc.SetActiveAccount(context.Background(), "u-1", "")
	if !apperrors.IsBadRequest(err) {
		t.Fatalf("want bad-request, got %v", err)
	}
}

func TestSetActiveAccount_EmitsChangedEventOnFirstSet(t *testing.T) {
	sink := &prefsCaptureSink{}
	svc := newPrefsServiceWithAudit(sink)

	if err := svc.SetActiveAccount(context.Background(), "u-1", "acc-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("want 1 audit event on first set, got %d", len(sink.events))
	}
	assertActiveAccountChangedEvent(t, sink.events[0], "u-1", "", "acc-1")
}

// assertActiveAccountChangedEvent verifies every field on a
// user_active_account_changed event. Extracted to keep individual tests
// under the gocyclo budget while covering the full event shape.
func assertActiveAccountChangedEvent(t *testing.T, e audit.Event, userID, previousID, newID string) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EventType", e.EventType, "user_active_account_changed"},
		{"Service", e.Service, "identity-service"},
		{"ActorType", string(e.ActorType), string(audit.ActorTypeUser)},
		{"ActorID", e.ActorID, userID},
		{"SubjectID", e.SubjectID, userID},
		{"ResourceKind", string(e.ResourceKind), string(audit.ResourceKindEndpoint)},
		{"ResourcePath", e.ResourcePath, "identity-service/endpoint/set_active_account"},
		{"Decision", e.Decision, audit.DecisionAllow},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("event.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if prev, _ := e.Attrs["previous_account_id"].(string); prev != previousID {
		t.Errorf("attrs.previous_account_id = %q, want %q", prev, previousID)
	}
	if got, _ := e.Attrs["new_account_id"].(string); got != newID {
		t.Errorf("attrs.new_account_id = %q, want %q", got, newID)
	}
}

func TestSetActiveAccount_EmitsOnChange(t *testing.T) {
	sink := &prefsCaptureSink{}
	svc := newPrefsServiceWithAudit(sink)
	ctx := context.Background()

	_ = svc.SetActiveAccount(ctx, "u-1", "acc-1")
	_ = svc.SetActiveAccount(ctx, "u-1", "acc-2")

	if len(sink.events) != 2 {
		t.Fatalf("want 2 audit events (both changes), got %d", len(sink.events))
	}
	if prev, _ := sink.events[1].Attrs["previous_account_id"].(string); prev != "acc-1" {
		t.Errorf("second event previous_account_id = %q, want acc-1", prev)
	}
}

func TestSetActiveAccount_SilentWhenValueUnchanged(t *testing.T) {
	sink := &prefsCaptureSink{}
	svc := newPrefsServiceWithAudit(sink)
	ctx := context.Background()

	_ = svc.SetActiveAccount(ctx, "u-1", "acc-1")
	_ = svc.SetActiveAccount(ctx, "u-1", "acc-1")

	if len(sink.events) != 1 {
		t.Fatalf("want 1 audit event (repeat should be silent), got %d", len(sink.events))
	}
}

var errPrefsAuditFailure = errors.New("simulated audit transport failure")

func TestSetActiveAccount_AuditFailureSurfaces(t *testing.T) {
	sink := &prefsCaptureSink{err: errPrefsAuditFailure}
	svc := newPrefsServiceWithAudit(sink)

	err := svc.SetActiveAccount(context.Background(), "u-1", "acc-1")
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !errors.Is(err, errPrefsAuditFailure) {
		t.Errorf("want wrapped audit failure, got %v", err)
	}
}

func TestSetActiveAccount_StampsUpdatedAtViaClock(t *testing.T) {
	repo := memory.NewUserPreferencesRepository()
	frozen := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	svc := application.NewUserPreferencesService(repo).WithClock(func() time.Time { return frozen })

	if err := svc.SetActiveAccount(context.Background(), "u-1", "acc-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, _ := repo.Get(context.Background(), "u-1")
	if !got.UpdatedAt.Equal(frozen) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, frozen)
	}
}

func TestNewUserPreferencesService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("want panic on nil repo")
		}
	}()
	_ = application.NewUserPreferencesService(nil)
}
