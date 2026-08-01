package http_test

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/email"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/adapters/outbound/memory"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/entitlements-service/internal/domain"
)

// seedTransferHandler bootstraps a handler over a real memory repo
// seeded with an owner + member seat. Returns the handler, the
// account ID, and the frozen clock instant the service reads —
// tests craft X-Requester-Auth-Time headers relative to that instant
// so freshness arithmetic is deterministic.
func seedTransferHandler(t *testing.T) (*http.Handler, string, time.Time) {
	t.Helper()
	acctRepo := memory.NewAccountRepository()
	invRepo := memory.NewInviteRepository()
	frozen := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	acctSvc := application.NewAccountService(acctRepo).
		WithAudit(audit.New(audit.NoopSink{}), "entitlements-service").
		WithClock(func() time.Time { return frozen })
	invSvc := application.NewInviteService(acctRepo, invRepo, email.NewNoopSender(), application.InviteConfig{
		TTL:              7 * 24 * time.Hour,
		SignupURLPattern: "https://example.test/accept?token={{token}}",
	}).WithAudit(audit.New(audit.NoopSink{}), "entitlements-service")

	acc, err := acctRepo.UpsertPersonalAccount(context.Background(), "owner-1", "owner@example.com")
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	acctRepo.AddMemberSeat(acc.ID, "member-1", domain.RoleMember)
	return http.NewHandler(acctSvc, invSvc, testLogger()), acc.ID, frozen
}

func doTransferOwnership(t *testing.T, h *http.Handler, accountID, requesterUserID, authTime, bodyJSON string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(stdhttp.MethodPost,
		"/accounts/"+accountID+"/transfer-ownership",
		strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	if requesterUserID != "" {
		req.Header.Set("X-Requester-User-ID", requesterUserID)
	}
	if authTime != "" {
		req.Header.Set("X-Requester-Auth-Time", authTime)
	}
	w := httptest.NewRecorder()
	http.NewRouter(h, testLogger()).ServeHTTP(w, req)
	return w
}

func TestTransferOwnership_HappyPath_Returns204(t *testing.T) {
	h, accountID, frozen := seedTransferHandler(t)
	authTime := frozen.Add(-1 * time.Minute).Format(time.RFC3339Nano)

	w := doTransferOwnership(t, h, accountID, "owner-1", authTime, `{"target_user_id":"member-1"}`)

	if w.Code != stdhttp.StatusNoContent {
		t.Fatalf("status = %d body=%s, want 204", w.Code, w.Body.String())
	}
}

func TestTransferOwnership_StaleAuth_Returns403(t *testing.T) {
	h, accountID, frozen := seedTransferHandler(t)
	authTime := frozen.Add(-10 * time.Minute).Format(time.RFC3339Nano)

	w := doTransferOwnership(t, h, accountID, "owner-1", authTime, `{"target_user_id":"member-1"}`)

	if w.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestTransferOwnership_NonOwner_Returns403(t *testing.T) {
	h, accountID, frozen := seedTransferHandler(t)
	authTime := frozen.Add(-30 * time.Second).Format(time.RFC3339Nano)

	// member-1 (not owner) tries to transfer to a stranger.
	w := doTransferOwnership(t, h, accountID, "member-1", authTime, `{"target_user_id":"stranger"}`)

	if w.Code != stdhttp.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestTransferOwnership_UnknownTarget_Returns404(t *testing.T) {
	h, accountID, frozen := seedTransferHandler(t)
	authTime := frozen.Add(-30 * time.Second).Format(time.RFC3339Nano)

	w := doTransferOwnership(t, h, accountID, "owner-1", authTime, `{"target_user_id":"ghost"}`)

	if w.Code != stdhttp.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestTransferOwnership_MissingRequesterHeader_Returns400(t *testing.T) {
	h, accountID, frozen := seedTransferHandler(t)
	authTime := frozen.Add(-30 * time.Second).Format(time.RFC3339Nano)

	w := doTransferOwnership(t, h, accountID, "", authTime, `{"target_user_id":"member-1"}`)

	if w.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestTransferOwnership_MissingAuthTimeHeader_Returns400(t *testing.T) {
	h, accountID, _ := seedTransferHandler(t)

	w := doTransferOwnership(t, h, accountID, "owner-1", "", `{"target_user_id":"member-1"}`)

	if w.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestTransferOwnership_MalformedAuthTimeHeader_Returns400(t *testing.T) {
	h, accountID, _ := seedTransferHandler(t)

	w := doTransferOwnership(t, h, accountID, "owner-1", "not-a-timestamp", `{"target_user_id":"member-1"}`)

	if w.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestTransferOwnership_MalformedBody_Returns400(t *testing.T) {
	h, accountID, frozen := seedTransferHandler(t)
	authTime := frozen.Add(-30 * time.Second).Format(time.RFC3339Nano)

	w := doTransferOwnership(t, h, accountID, "owner-1", authTime, `not-json`)

	if w.Code != stdhttp.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
