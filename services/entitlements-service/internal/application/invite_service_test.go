package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

type stubEmail struct {
	sends []ports.InviteEmail
	err   error
}

func (s *stubEmail) SendInvite(_ context.Context, msg ports.InviteEmail) error {
	s.sends = append(s.sends, msg)
	return s.err
}

// newInviteSvc seeds a personal account for ownerUserID and returns
// an InviteService wired against fresh in-memory repos + a stub email
// adapter. The _ in the signature is a placeholder kept for symmetry
// with tests that pass an intended-invitee email — the seeding does
// not currently need it.
func newInviteSvc(t *testing.T, ownerUserID, _ string) (svc *application.InviteService, acctRepo *memory.AccountRepository, invRepo *memory.InviteRepository, email *stubEmail, accountID string, ownerSeatID string) {
	t.Helper()
	acctRepo = memory.NewAccountRepository()
	invRepo = memory.NewInviteRepository()
	email = &stubEmail{}
	svc = application.NewInviteService(acctRepo, invRepo, email, application.InviteConfig{
		TTL:              7 * 24 * time.Hour,
		SignupURLPattern: "https://example.test/accept?token={{token}}",
	}).WithAudit(audit.New(audit.NoopSink{}), "entitlements-service")

	// Seed an owner personal account so the RBAC + seat-count checks
	// have realistic input.
	acc, err := acctRepo.UpsertPersonalAccount(context.Background(), ownerUserID, "owner@example.com")
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	seats, _ := acctRepo.ListByAccount(context.Background(), acc.ID)
	return svc, acctRepo, invRepo, email, acc.ID, seats[0].ID
}

func TestInvite_HappyPathEmitsAndSends(t *testing.T) {
	// Arrange
	svc, acctRepo, invRepo, email, accountID, _ := newInviteSvc(t, "owner-1", "invitee@example.com")
	acctRepo.SetSeatAllowance(accountID, 10) // Club-tier allowance

	// Act
	inv, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID:       accountID,
		RequesterUserID: "owner-1",
		InvitedEmail:    "invitee@example.com",
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertInviteShape(t, inv)
	assertEmailSent(t, email, inv, "invitee@example.com")
	assertInvitePersisted(t, invRepo, accountID, 1)
}

// assertInviteShape checks fields we expect populated on the freshly
// returned invite.
func assertInviteShape(t *testing.T, inv *domain.Invite) {
	t.Helper()
	if inv.ID == "" {
		t.Error("expected invite ID")
	}
	if inv.RawToken == "" {
		t.Error("expected raw token on returned invite")
	}
	if inv.TokenHash == "" {
		t.Error("expected token hash on stored invite")
	}
	if inv.RawToken == inv.TokenHash {
		t.Error("raw token and hash must not be equal")
	}
}

// assertEmailSent verifies the email adapter received the right
// message with the raw token embedded in the URL.
func assertEmailSent(t *testing.T, email *stubEmail, inv *domain.Invite, wantTo string) {
	t.Helper()
	if len(email.sends) != 1 {
		t.Fatalf("expected 1 email send, got %d", len(email.sends))
	}
	sent := email.sends[0]
	if sent.ToEmail != wantTo {
		t.Errorf("email.ToEmail = %q, want %q", sent.ToEmail, wantTo)
	}
	if !strings.Contains(sent.SignupURL, inv.RawToken) {
		t.Errorf("signup URL %q does not contain raw token", sent.SignupURL)
	}
}

// assertInvitePersisted checks the open-invite count on the account.
func assertInvitePersisted(t *testing.T, invRepo *memory.InviteRepository, accountID string, want int) {
	t.Helper()
	n, _ := invRepo.CountOpen(context.Background(), accountID)
	if n != want {
		t.Errorf("open invite count = %d, want %d", n, want)
	}
}

func TestInvite_RejectsWhenRequesterIsNotOwner(t *testing.T) {
	// Arrange — requester is not an owner-role seat on this account
	// (they aren't a seat at all here). Only owners can invite per AC.
	svc, acctRepo, _, _, accountID, _ := newInviteSvc(t, "owner-1", "invitee@example.com")
	acctRepo.SetSeatAllowance(accountID, 10)

	// Act
	_, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID:       accountID,
		RequesterUserID: "not-owner",
		InvitedEmail:    "invitee@example.com",
	})

	// Assert
	if err == nil {
		t.Fatal("expected forbidden error, got nil")
	}
	if !apperrors.IsForbidden(err) {
		t.Errorf("expected forbidden, got %v", err)
	}
}

func TestInvite_RejectsWhenSeatLimitReached(t *testing.T) {
	// Arrange — allowance 1 (personal-account default), owner takes
	// the seat, so adding another via invite would exceed.
	svc, _, _, _, accountID, _ := newInviteSvc(t, "owner-1", "invitee@example.com")
	// No SetSeatAllowance -> default 1

	// Act
	_, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID:       accountID,
		RequesterUserID: "owner-1",
		InvitedEmail:    "invitee@example.com",
	})

	// Assert
	if err == nil {
		t.Fatal("expected conflict / limit error, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected conflict, got %v", err)
	}
}

func TestInvite_CountsOpenInvitesTowardsSeatLimit(t *testing.T) {
	// Arrange — allowance 2, owner already occupies 1, an open invite
	// occupies the second. A second invite should be refused because
	// we don't want the account to reach state where accepting all
	// open invites would exceed the allowance.
	svc, acctRepo, _, _, accountID, _ := newInviteSvc(t, "owner-1", "first@example.com")
	acctRepo.SetSeatAllowance(accountID, 2)
	if _, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID: accountID, RequesterUserID: "owner-1", InvitedEmail: "first@example.com",
	}); err != nil {
		t.Fatalf("first invite: %v", err)
	}

	// Act — second invite (owner + 1 open invite = 2, allowance = 2)
	_, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID: accountID, RequesterUserID: "owner-1", InvitedEmail: "second@example.com",
	})

	// Assert
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	if !apperrors.IsConflict(err) {
		t.Errorf("expected conflict, got %v", err)
	}
}

func TestInvite_ValidationRejectsEmptyEmail(t *testing.T) {
	svc, acctRepo, _, _, accountID, _ := newInviteSvc(t, "owner-1", "-")
	acctRepo.SetSeatAllowance(accountID, 10)

	_, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID: accountID, RequesterUserID: "owner-1", InvitedEmail: "",
	})
	if err == nil || !apperrors.IsBadRequest(err) {
		t.Errorf("expected bad-request, got %v", err)
	}
}

func TestInvite_SetsExpiryFromConfig(t *testing.T) {
	// Arrange
	svc, acctRepo, _, _, accountID, _ := newInviteSvc(t, "owner-1", "invitee@example.com")
	acctRepo.SetSeatAllowance(accountID, 10)

	// Act
	before := time.Now().UTC()
	inv, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID: accountID, RequesterUserID: "owner-1", InvitedEmail: "invitee@example.com",
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert — expiry is between (before + TTL) and (after + TTL)
	ttl := 7 * 24 * time.Hour
	if inv.ExpiresAt.Before(before.Add(ttl)) || inv.ExpiresAt.After(after.Add(ttl)) {
		t.Errorf("ExpiresAt = %v, want in [%v, %v]", inv.ExpiresAt, before.Add(ttl), after.Add(ttl))
	}
}

func TestInvite_EmailFailureSurfaces(t *testing.T) {
	// Arrange — email send failure must fail the invite so the
	// account state doesn't have an invite record no one was
	// notified about.
	svc, acctRepo, _, email, accountID, _ := newInviteSvc(t, "owner-1", "invitee@example.com")
	acctRepo.SetSeatAllowance(accountID, 10)
	email.err = errors.New("simulated smtp failure")

	// Act
	_, err := svc.Invite(context.Background(), application.InviteRequest{
		AccountID: accountID, RequesterUserID: "owner-1", InvitedEmail: "invitee@example.com",
	})

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, email.err) {
		t.Errorf("expected wrapped email error, got %v", err)
	}
}

func TestNewInviteService_NilPanics(t *testing.T) {
	cases := []struct {
		name  string
		build func()
	}{
		{"nil account repo", func() {
			_ = application.NewInviteService(nil, memory.NewInviteRepository(), &stubEmail{}, application.InviteConfig{TTL: time.Hour, SignupURLPattern: "?t={{token}}"})
		}},
		{"nil invite repo", func() {
			_ = application.NewInviteService(memory.NewAccountRepository(), nil, &stubEmail{}, application.InviteConfig{TTL: time.Hour, SignupURLPattern: "?t={{token}}"})
		}},
		{"nil email", func() {
			_ = application.NewInviteService(memory.NewAccountRepository(), memory.NewInviteRepository(), nil, application.InviteConfig{TTL: time.Hour, SignupURLPattern: "?t={{token}}"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected panic")
				}
			}()
			tc.build()
		})
	}
}
