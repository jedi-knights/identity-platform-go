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

// newSvcWithPlan builds the service against a memory repo seeded with a
// single plan matching planCode. The service's plan repository is the
// same repo so ActivatePlan sees the seeded catalog.
func newSvcWithPlan(planCode string) (*application.AccountService, *memory.AccountRepository, *captureSink) {
	repo := memory.NewAccountRepository()
	repo.AddPlan(domain.Plan{
		ID: "plan-" + planCode, Code: planCode,
		DisplayName: planCode, Tier: "free", SeatAllowance: 1,
	})
	sink := &captureSink{}
	svc := application.NewAccountService(repo).
		WithAudit(audit.New(sink), "entitlements-service").
		WithPlans(repo)
	return svc, repo, sink
}

// account creates a personal account and returns its ID so the plan
// activation has a real FK to write against.
func account(t *testing.T, svc *application.AccountService, userID, email string) string {
	t.Helper()
	acc, _, err := svc.CreatePersonalAccount(context.Background(), userID, email)
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return acc.ID
}

func TestActivatePlan_CreatesRowAndEmitsAudit(t *testing.T) {
	svc, _, sink := newSvcWithPlan("touchline-free")
	accountID := account(t, svc, "u1", "u1@example.com")

	res, err := svc.ActivatePlan(context.Background(), application.ActivatePlanRequest{
		AccountID: accountID, PlanCode: "touchline-free",
	})
	if err != nil {
		t.Fatalf("ActivatePlan: %v", err)
	}
	assertCreatedResult(t, res, accountID)
	if !containsEvent(sink.events, "plan_activated") {
		t.Errorf("expected plan_activated event, got %v", eventTypes(sink.events))
	}
}

func assertCreatedResult(t *testing.T, res *application.ActivatePlanResult, accountID string) {
	t.Helper()
	if !res.Created {
		t.Fatal("expected created=true on first activation")
	}
	if res.Row.AccountID != accountID || res.Row.PlanID != "plan-touchline-free" {
		t.Errorf("row = %+v", res.Row)
	}
	if res.Plan == nil || res.Plan.Tier != "free" {
		t.Errorf("plan = %+v, want tier=free", res.Plan)
	}
}

func TestActivatePlan_IsIdempotentAndSkipsAudit(t *testing.T) {
	svc, _, sink := newSvcWithPlan("touchline-free")
	accountID := account(t, svc, "u1", "u1@example.com")

	if _, err := svc.ActivatePlan(context.Background(), application.ActivatePlanRequest{
		AccountID: accountID, PlanCode: "touchline-free",
	}); err != nil {
		t.Fatalf("first activation: %v", err)
	}
	res, err := svc.ActivatePlan(context.Background(), application.ActivatePlanRequest{
		AccountID: accountID, PlanCode: "touchline-free",
	})
	if err != nil {
		t.Fatalf("second activation: %v", err)
	}
	if res.Created {
		t.Error("expected created=false on idempotent replay")
	}
	// Only ONE plan_activated event should have been emitted.
	if n := countEvent(sink.events, "plan_activated"); n != 1 {
		t.Errorf("expected 1 plan_activated event, got %d", n)
	}
}

func TestActivatePlan_DifferentPlanConflicts(t *testing.T) {
	svc, repo, _ := newSvcWithPlan("touchline-free")
	repo.AddPlan(domain.Plan{
		ID: "plan-touchline-club", Code: "touchline-club",
		DisplayName: "Club", Tier: "club", SeatAllowance: 25,
	})
	accountID := account(t, svc, "u1", "u1@example.com")

	if _, err := svc.ActivatePlan(context.Background(), application.ActivatePlanRequest{
		AccountID: accountID, PlanCode: "touchline-free",
	}); err != nil {
		t.Fatalf("first activation: %v", err)
	}

	_, err := svc.ActivatePlan(context.Background(), application.ActivatePlanRequest{
		AccountID: accountID, PlanCode: "touchline-club",
	})
	if err == nil {
		t.Fatal("expected conflict, got nil")
	}
	var ae *apperrors.AppError
	if !errorsAs(err, &ae) || ae.Code() != apperrors.ErrCodeConflict {
		t.Errorf("expected ErrCodeConflict, got %v", err)
	}
}

func TestActivatePlan_UnknownPlanCode(t *testing.T) {
	svc, _, _ := newSvcWithPlan("touchline-free")
	accountID := account(t, svc, "u1", "u1@example.com")

	_, err := svc.ActivatePlan(context.Background(), application.ActivatePlanRequest{
		AccountID: accountID, PlanCode: "ghost",
	})
	if err == nil || !apperrors.IsNotFound(err) {
		t.Errorf("expected not-found, got %v", err)
	}
}

func TestActivatePlan_ValidationRejectsEmptyFields(t *testing.T) {
	svc, _, _ := newSvcWithPlan("touchline-free")

	cases := []struct {
		name string
		req  application.ActivatePlanRequest
	}{
		{"empty account_id", application.ActivatePlanRequest{PlanCode: "touchline-free"}},
		{"empty plan_code", application.ActivatePlanRequest{AccountID: "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.ActivatePlan(context.Background(), tc.req)
			if err == nil || !apperrors.IsBadRequest(err) {
				t.Errorf("expected bad-request, got %v", err)
			}
		})
	}
}

func containsEvent(events []audit.Event, evtType string) bool {
	return countEvent(events, evtType) > 0
}

func countEvent(events []audit.Event, evtType string) int {
	n := 0
	for _, e := range events {
		if e.EventType == evtType {
			n++
		}
	}
	return n
}

func eventTypes(events []audit.Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.EventType
	}
	return out
}

// errorsAs is a thin alias for errors.As so the call site in the
// conflict test reads at the same abstraction level as the surrounding
// apperrors helpers.
func errorsAs(err error, target any) bool {
	var appErr *apperrors.AppError
	if _, ok := target.(**apperrors.AppError); ok {
		if errors.As(err, &appErr) {
			*target.(**apperrors.AppError) = appErr
			return true
		}
	}
	return false
}
