package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// removeSeatFixture bootstraps an account with an owner plus one
// additional member seat (added directly via the underlying repo's
// internal state to keep this fixture from depending on E7-S2 invite
// acceptance, which is still a future story). Returns the service,
// audit sink, and (accountID, ownerUserID, memberUserID) so tests
// can assert against a real (repo, service) pair.
func removeSeatFixture(t *testing.T) (*application.AccountService, *prefsCaptureSink, string, string, string) {
	t.Helper()
	repo := memory.NewAccountRepository()
	sink := &prefsCaptureSink{}
	svc := application.NewAccountService(repo).WithAudit(audit.New(sink), "entitlements-service")

	acc, err := repo.UpsertPersonalAccount(context.Background(), "owner-user", "o@example.com")
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	// Add a member seat via a second personal-account upsert on a
	// different account, then copy the seat over — the memory repo
	// exposes no direct "add member" hook (invite-accept is a future
	// story), so we lean on the test-only escape hatch: overwrite
	// the seats slice through a helper.
	repo.AddMemberSeat(acc.ID, "member-user", domain.RoleMember)

	return svc, sink, acc.ID, "owner-user", "member-user"
}

// prefsCaptureSink is reused from user_preferences tests; redeclared
// here so this file is self-contained.
type prefsCaptureSink struct {
	events []audit.Event
	err    error
}

func (c *prefsCaptureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

func TestRemoveSeat_HappyPath(t *testing.T) {
	svc, sink, accountID, owner, member := removeSeatFixture(t)

	err := svc.RemoveSeat(context.Background(), application.RemoveSeatRequest{
		AccountID:       accountID,
		RequesterUserID: owner,
		TargetUserID:    member,
	})
	if err != nil {
		t.Fatalf("RemoveSeat: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(sink.events))
	}
	assertSeatRemovedEvent(t, sink.events[0], owner, member, accountID)
}

// assertSeatRemovedEvent keeps TestRemoveSeat_HappyPath under gocyclo
// while covering every observable field on the emitted event.
func assertSeatRemovedEvent(t *testing.T, e audit.Event, ownerID, memberID, accountID string) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EventType", e.EventType, "seat_removed"},
		{"ActorID", e.ActorID, ownerID},
		{"SubjectID", e.SubjectID, memberID},
		{"Decision", e.Decision, audit.DecisionAllow},
		{"ResourcePath", e.ResourcePath, "entitlements-service/endpoint/accounts.seats.remove"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("event.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if got, _ := e.Attrs["account_id"].(string); got != accountID {
		t.Errorf("attrs.account_id = %q, want %q", got, accountID)
	}
	if role, _ := e.Attrs["removed_role"].(string); role != "member" {
		t.Errorf("attrs.removed_role = %q, want member", role)
	}
}

func TestRemoveSeat_OwnerCannotRemoveSelf_Conflict(t *testing.T) {
	svc, _, accountID, owner, _ := removeSeatFixture(t)

	err := svc.RemoveSeat(context.Background(), application.RemoveSeatRequest{
		AccountID:       accountID,
		RequesterUserID: owner,
		TargetUserID:    owner,
	})
	if !apperrors.IsConflict(err) {
		t.Fatalf("want conflict, got %v", err)
	}
}

func TestRemoveSeat_NonOwnerRequester_Forbidden(t *testing.T) {
	svc, _, accountID, _, member := removeSeatFixture(t)

	// member tries to remove owner
	err := svc.RemoveSeat(context.Background(), application.RemoveSeatRequest{
		AccountID:       accountID,
		RequesterUserID: member,
		TargetUserID:    "owner-user",
	})
	if !apperrors.IsForbidden(err) {
		t.Fatalf("want forbidden, got %v", err)
	}
}

func TestRemoveSeat_RequesterNotSeat_Forbidden(t *testing.T) {
	svc, _, accountID, _, _ := removeSeatFixture(t)

	err := svc.RemoveSeat(context.Background(), application.RemoveSeatRequest{
		AccountID:       accountID,
		RequesterUserID: "stranger-user",
		TargetUserID:    "member-user",
	})
	// Non-member requester collapses to forbidden — the API must not
	// disclose account membership to non-members.
	if !apperrors.IsForbidden(err) {
		t.Fatalf("want forbidden, got %v", err)
	}
}

func TestRemoveSeat_TargetNotOnAccount_NotFound(t *testing.T) {
	svc, _, accountID, owner, _ := removeSeatFixture(t)

	err := svc.RemoveSeat(context.Background(), application.RemoveSeatRequest{
		AccountID:       accountID,
		RequesterUserID: owner,
		TargetUserID:    "ghost-user",
	})
	if !apperrors.IsNotFound(err) {
		t.Fatalf("want not-found, got %v", err)
	}
}

func TestRemoveSeat_ValidationRejectsEmptyFields(t *testing.T) {
	svc, _, accountID, owner, member := removeSeatFixture(t)
	ctx := context.Background()

	cases := []application.RemoveSeatRequest{
		{AccountID: "", RequesterUserID: owner, TargetUserID: member},
		{AccountID: accountID, RequesterUserID: "", TargetUserID: member},
		{AccountID: accountID, RequesterUserID: owner, TargetUserID: ""},
	}
	for _, req := range cases {
		if err := svc.RemoveSeat(ctx, req); !apperrors.IsBadRequest(err) {
			t.Errorf("req=%+v want bad-request, got %v", req, err)
		}
	}
}

var errRemoveSeatAuditFailure = errors.New("simulated audit transport failure")

func TestRemoveSeat_AuditFailureSurfaces(t *testing.T) {
	svc, sink, accountID, owner, member := removeSeatFixture(t)
	sink.err = errRemoveSeatAuditFailure

	err := svc.RemoveSeat(context.Background(), application.RemoveSeatRequest{
		AccountID:       accountID,
		RequesterUserID: owner,
		TargetUserID:    member,
	})
	if err == nil {
		t.Fatal("want audit failure to surface, got nil")
	}
	if !errors.Is(err, errRemoveSeatAuditFailure) {
		t.Errorf("want wrapped audit failure, got %v", err)
	}
}
