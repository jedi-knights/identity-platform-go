package http_test

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/email"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// seedRemoveSeatHandler bootstraps a handler over a real memory repo
// seeded with an owner plus a member seat. Returns (handler, accountID)
// so the individual test can construct the DELETE URL from the path
// parts it wants to probe.
func seedRemoveSeatHandler(t *testing.T) (*http.Handler, string) {
	t.Helper()
	acctRepo := memory.NewAccountRepository()
	invRepo := memory.NewInviteRepository()
	acctSvc := application.NewAccountService(acctRepo).
		WithAudit(audit.New(audit.NoopSink{}), "entitlements-service")
	invSvc := application.NewInviteService(acctRepo, invRepo, email.NewNoopSender(), application.InviteConfig{
		TTL:              7 * 24 * time.Hour,
		SignupURLPattern: "https://example.test/accept?token={{token}}",
	}).WithAudit(audit.New(audit.NoopSink{}), "entitlements-service")

	acc, err := acctRepo.UpsertPersonalAccount(context.Background(), "owner-1", "owner@example.com")
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	acctRepo.AddMemberSeat(acc.ID, "member-1", domain.RoleMember)
	return http.NewHandler(acctSvc, invSvc, testLogger()), acc.ID
}

// doDeleteSeat drives the endpoint through NewRouter so path-value
// extraction is exercised end-to-end (the handler itself calls
// r.PathValue, which requires the mux to have parsed the pattern).
func doDeleteSeat(t *testing.T, h *http.Handler, accountID, targetUserID, requesterUserID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(stdhttp.MethodDelete, "/accounts/"+accountID+"/seats/"+targetUserID, nil)
	if requesterUserID != "" {
		req.Header.Set("X-Requester-User-ID", requesterUserID)
	}
	w := httptest.NewRecorder()
	http.NewRouter(h, testLogger()).ServeHTTP(w, req)
	return w
}

func TestRemoveSeat_HappyPath_Returns204(t *testing.T) {
	h, accountID := seedRemoveSeatHandler(t)

	w := doDeleteSeat(t, h, accountID, "member-1", "owner-1")

	if w.Code != stdhttp.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
}

func TestRemoveSeat_OwnerCannotRemoveSelf_Returns409(t *testing.T) {
	h, accountID := seedRemoveSeatHandler(t)

	w := doDeleteSeat(t, h, accountID, "owner-1", "owner-1")

	if w.Code != stdhttp.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

func TestRemoveSeat_NonOwnerRequester_Returns403(t *testing.T) {
	h, accountID := seedRemoveSeatHandler(t)

	// member-1 tries to remove owner-1 — must be forbidden.
	w := doDeleteSeat(t, h, accountID, "owner-1", "member-1")

	if w.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestRemoveSeat_StrangerRequester_Returns403(t *testing.T) {
	h, accountID := seedRemoveSeatHandler(t)

	// Requester has no seat on this account at all — must collapse
	// to 403, not 404, so the API does not disclose membership.
	w := doDeleteSeat(t, h, accountID, "member-1", "stranger-1")

	if w.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestRemoveSeat_UnknownTargetOnAccount_Returns404(t *testing.T) {
	h, accountID := seedRemoveSeatHandler(t)

	w := doDeleteSeat(t, h, accountID, "ghost-user", "owner-1")

	if w.Code != stdhttp.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestRemoveSeat_MissingRequesterHeader_Returns400(t *testing.T) {
	h, accountID := seedRemoveSeatHandler(t)

	w := doDeleteSeat(t, h, accountID, "member-1", "")

	if w.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
