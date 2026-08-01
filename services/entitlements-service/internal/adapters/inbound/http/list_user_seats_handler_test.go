package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jedi-knights/go-platform/testutil"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/ports"
)

// newSwitcherHandler wires a Handler against a fresh in-memory repo
// and returns both, so tests can seed accounts through the repo and
// exercise the handler through its ServeHTTP-equivalent entry.
func newSwitcherHandler(t *testing.T) (*Handler, *memory.AccountRepository) {
	t.Helper()
	repo := memory.NewAccountRepository()
	accSvc := application.NewAccountService(repo)
	invSvc := application.NewInviteService(
		repo, &fakeInviteRepoForHandlerConstruction{}, &fakeEmailForHandlerConstruction{},
		application.InviteConfig{TTL: 24, SignupURLPattern: "https://example.com/{{token}}"},
	)
	return NewHandler(accSvc, invSvc, testutil.NewTestLogger()), repo
}

// fakeInviteRepoForHandlerConstruction / fakeEmailForHandlerConstruction
// satisfy the InviteService constructor without adding behaviour — the
// list-user-seats tests never touch the invite path. Naming them
// verbosely stops future readers wondering if they belong in the seat
// tests.
type fakeInviteRepoForHandlerConstruction struct{}

func (fakeInviteRepoForHandlerConstruction) Insert(context.Context, domain.Invite) (*domain.Invite, error) {
	return nil, nil
}

func (fakeInviteRepoForHandlerConstruction) CountOpen(context.Context, string) (int, error) {
	return 0, nil
}

type fakeEmailForHandlerConstruction struct{}

func (fakeEmailForHandlerConstruction) SendInvite(context.Context, ports.InviteEmail) error {
	return nil
}

func doListUserSeats(t *testing.T, h *Handler, userID, requester string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/users/"+userID+"/seats", nil)
	req.SetPathValue("user_id", userID)
	if requester != "" {
		req.Header.Set(requesterHeader, requester)
	}
	w := httptest.NewRecorder()
	h.ListUserSeats(w, req)
	return w
}

func TestListUserSeats_Success_ReturnsSeatsArray(t *testing.T) {
	h, repo := newSwitcherHandler(t)
	_, err := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doListUserSeats(t, h, "u-1", "u-1")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body listUserSeatsResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Seats) != 1 {
		t.Fatalf("want 1 seat, got %d", len(body.Seats))
	}
	if body.Seats[0].Role != "owner" {
		t.Errorf("role = %q, want owner", body.Seats[0].Role)
	}
	if body.Seats[0].Plan != nil {
		t.Errorf("plan = %+v, want null (no plan attached)", body.Seats[0].Plan)
	}
}

func TestListUserSeats_EmptyForUserWithoutSeats(t *testing.T) {
	h, _ := newSwitcherHandler(t)

	w := doListUserSeats(t, h, "u-empty", "u-empty")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty list, not 404)", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"seats":[]`) {
		t.Errorf("body = %s, want seats:[]", w.Body.String())
	}
}

func TestListUserSeats_MissingRequesterHeader_Returns400(t *testing.T) {
	h, _ := newSwitcherHandler(t)

	w := doListUserSeats(t, h, "u-1", "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestListUserSeats_RequesterMismatch_Returns403(t *testing.T) {
	h, _ := newSwitcherHandler(t)

	w := doListUserSeats(t, h, "u-1", "u-99")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestListUserSeats_PlanSerializesAsNullWhenAbsent(t *testing.T) {
	h, repo := newSwitcherHandler(t)
	_, _ = repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")

	w := doListUserSeats(t, h, "u-1", "u-1")

	// Verify the JSON contains `"plan":null` literally rather than an
	// empty-object serialisation ("plan":{}). login-ui distinguishes
	// the two cases explicitly.
	if !strings.Contains(w.Body.String(), `"plan":null`) {
		t.Errorf("body = %s, want plan:null", w.Body.String())
	}
}

func TestListUserSeats_PlanIncludedWhenAttached(t *testing.T) {
	h, repo := newSwitcherHandler(t)
	acc, _ := repo.UpsertPersonalAccount(context.Background(), "u-1", "u1@example.com")
	repo.SetActivePlan(acc.ID, domain.PlanSummary{
		ID:          "plan-uuid",
		Code:        "touchline-club",
		DisplayName: "Touchline Club",
	})

	w := doListUserSeats(t, h, "u-1", "u-1")

	var body listUserSeatsResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Seats[0].Plan == nil || body.Seats[0].Plan.Code != "touchline-club" {
		t.Errorf("plan = %+v, want touchline-club", body.Seats[0].Plan)
	}
}
