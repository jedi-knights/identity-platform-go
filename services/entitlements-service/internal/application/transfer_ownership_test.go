package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// transferFixture bootstraps an account with an owner + member seat
// and returns the service wired against a frozen clock (so freshness
// arithmetic is deterministic) plus the audit sink.
func transferFixture(t *testing.T) (*application.AccountService, *prefsCaptureSink, string, string, string, time.Time) {
	t.Helper()
	repo := memory.NewAccountRepository()
	sink := &prefsCaptureSink{}
	// Freeze the clock at a fixed instant; tests pass authTime values
	// relative to this baseline so nothing races real wall time.
	frozen := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	svc := application.NewAccountService(repo).
		WithAudit(audit.New(sink), "entitlements-service").
		WithClock(func() time.Time { return frozen })

	acc, err := repo.UpsertPersonalAccount(context.Background(), "owner-1", "o@example.com")
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	repo.AddMemberSeat(acc.ID, "member-1", domain.RoleMember)
	return svc, sink, acc.ID, "owner-1", "member-1", frozen
}

func TestTransferOwnership_HappyPath(t *testing.T) {
	svc, sink, accountID, owner, member, now := transferFixture(t)

	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   owner,
		RequesterAuthTime: now.Add(-1 * time.Minute), // 1 min old — well within 5-min window
		TargetUserID:      member,
	})
	if err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(sink.events))
	}
	assertOwnershipTransferredEvent(t, sink.events[0], owner, member, accountID)
}

// assertOwnershipTransferredEvent keeps the happy-path test under
// gocyclo while asserting every field on the emitted event.
func assertOwnershipTransferredEvent(t *testing.T, e audit.Event, prev, next, accountID string) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"EventType", e.EventType, "ownership_transferred"},
		{"ActorID", e.ActorID, prev},
		{"SubjectID", e.SubjectID, next},
		{"ResourcePath", e.ResourcePath, "entitlements-service/endpoint/accounts.transfer_ownership"},
		{"Decision", e.Decision, audit.DecisionAllow},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("event.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if got, _ := e.Attrs["previous_owner_id"].(string); got != prev {
		t.Errorf("attrs.previous_owner_id = %q, want %q", got, prev)
	}
	if got, _ := e.Attrs["new_owner_id"].(string); got != next {
		t.Errorf("attrs.new_owner_id = %q, want %q", got, next)
	}
	if got, _ := e.Attrs["account_id"].(string); got != accountID {
		t.Errorf("attrs.account_id = %q, want %q", got, accountID)
	}
}

func TestTransferOwnership_AppliesRoleSwap(t *testing.T) {
	// Verify the seats really flipped after a successful transfer.
	repo := memory.NewAccountRepository()
	frozen := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	svc := application.NewAccountService(repo).
		WithClock(func() time.Time { return frozen })

	acc, _ := repo.UpsertPersonalAccount(context.Background(), "owner-1", "o@example.com")
	repo.AddMemberSeat(acc.ID, "member-1", domain.RoleMember)

	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         acc.ID,
		RequesterUserID:   "owner-1",
		RequesterAuthTime: frozen.Add(-30 * time.Second),
		TargetUserID:      "member-1",
	})
	if err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}
	oldOwner, _ := repo.FindSeat(context.Background(), acc.ID, "owner-1")
	newOwner, _ := repo.FindSeat(context.Background(), acc.ID, "member-1")
	if oldOwner.Role != domain.RoleAdmin {
		t.Errorf("old owner role = %q, want admin (demoted)", oldOwner.Role)
	}
	if newOwner.Role != domain.RoleOwner {
		t.Errorf("new owner role = %q, want owner (promoted)", newOwner.Role)
	}
}

func TestTransferOwnership_StaleAuth_Forbidden(t *testing.T) {
	svc, sink, accountID, owner, member, now := transferFixture(t)

	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   owner,
		RequesterAuthTime: now.Add(-10 * time.Minute), // stale — outside 5-min window
		TargetUserID:      member,
	})
	if !apperrors.IsForbidden(err) {
		t.Fatalf("want forbidden, got %v", err)
	}
	// Staleness must fail closed: no swap, no audit.
	if len(sink.events) != 0 {
		t.Errorf("want 0 audit events on stale-auth failure, got %d", len(sink.events))
	}
}

func TestTransferOwnership_FutureAuth_BadRequest(t *testing.T) {
	svc, _, accountID, owner, member, now := transferFixture(t)

	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   owner,
		RequesterAuthTime: now.Add(10 * time.Second),
		TargetUserID:      member,
	})
	if !apperrors.IsBadRequest(err) {
		t.Fatalf("want bad-request for future auth_time, got %v", err)
	}
}

func TestTransferOwnership_NonOwnerRequester_Forbidden(t *testing.T) {
	svc, _, accountID, _, member, now := transferFixture(t)

	// member tries to transfer to themselves — must fail on RBAC before
	// same-user check (assertRequesterIsOwner runs after freshness
	// but before target lookup; use a distinct target to isolate).
	svc = svc.WithClock(func() time.Time { return now }) // keep fresh
	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   member,
		RequesterAuthTime: now,
		TargetUserID:      "someone-else",
	})
	if !apperrors.IsForbidden(err) {
		t.Fatalf("want forbidden, got %v", err)
	}
}

func TestTransferOwnership_TargetNotOnAccount_NotFound(t *testing.T) {
	svc, _, accountID, owner, _, now := transferFixture(t)

	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   owner,
		RequesterAuthTime: now,
		TargetUserID:      "ghost-user",
	})
	if !apperrors.IsNotFound(err) {
		t.Fatalf("want not-found, got %v", err)
	}
}

func TestTransferOwnership_SameUser_BadRequest(t *testing.T) {
	svc, _, accountID, owner, _, now := transferFixture(t)

	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   owner,
		RequesterAuthTime: now,
		TargetUserID:      owner,
	})
	if !apperrors.IsBadRequest(err) {
		t.Fatalf("want bad-request, got %v", err)
	}
}

func TestTransferOwnership_ValidationRejectsEmptyFields(t *testing.T) {
	svc, _, accountID, owner, member, now := transferFixture(t)
	ctx := context.Background()

	cases := []application.TransferOwnershipRequest{
		{AccountID: "", RequesterUserID: owner, RequesterAuthTime: now, TargetUserID: member},
		{AccountID: accountID, RequesterUserID: "", RequesterAuthTime: now, TargetUserID: member},
		{AccountID: accountID, RequesterUserID: owner, RequesterAuthTime: now, TargetUserID: ""},
		{AccountID: accountID, RequesterUserID: owner, TargetUserID: member}, // zero AuthTime
	}
	for _, req := range cases {
		if err := svc.TransferOwnership(ctx, req); !apperrors.IsBadRequest(err) {
			t.Errorf("req=%+v want bad-request, got %v", req, err)
		}
	}
}

var errTransferAuditFailure = errors.New("simulated audit transport failure")

func TestTransferOwnership_AuditFailureSurfaces(t *testing.T) {
	svc, sink, accountID, owner, member, now := transferFixture(t)
	sink.err = errTransferAuditFailure

	err := svc.TransferOwnership(context.Background(), application.TransferOwnershipRequest{
		AccountID:         accountID,
		RequesterUserID:   owner,
		RequesterAuthTime: now,
		TargetUserID:      member,
	})
	if err == nil {
		t.Fatal("want audit failure to surface, got nil")
	}
	if !errors.Is(err, errTransferAuditFailure) {
		t.Errorf("want wrapped audit failure, got %v", err)
	}
}
