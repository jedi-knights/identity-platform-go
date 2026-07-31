package http_test

import (
	"context"
	"encoding/json"
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
)

// seedOwnerAccount returns a Handler with a personal account already
// seeded for ownerUserID, plus that account's ID for the test to
// use in the URL path.
func seedOwnerAccount(t *testing.T, ownerUserID string, seatAllowance int) (*http.Handler, string) {
	t.Helper()
	acctRepo := memory.NewAccountRepository()
	invRepo := memory.NewInviteRepository()
	acctSvc := application.NewAccountService(acctRepo).
		WithAudit(audit.New(audit.NoopSink{}), "entitlements-service")
	invSvc := application.NewInviteService(acctRepo, invRepo, email.NewNoopSender(), application.InviteConfig{
		TTL:              7 * 24 * time.Hour,
		SignupURLPattern: "https://example.test/accept?token={{token}}",
	}).WithAudit(audit.New(audit.NoopSink{}), "entitlements-service")

	acc, err := acctRepo.UpsertPersonalAccount(context.Background(), ownerUserID, "owner@example.com")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	acctRepo.SetSeatAllowance(acc.ID, seatAllowance)

	return http.NewHandler(acctSvc, invSvc, testLogger()), acc.ID
}

func postInvite(t *testing.T, h *http.Handler, accountID, requesterUserID, bodyJSON string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(stdhttp.MethodPost, "/accounts/"+accountID+"/invites", strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	if requesterUserID != "" {
		req.Header.Set("X-Requester-User-ID", requesterUserID)
	}
	w := httptest.NewRecorder()
	http.NewRouter(h, testLogger()).ServeHTTP(w, req)
	return w
}

func TestCreateInvite_Returns201(t *testing.T) {
	// Arrange
	h, accountID := seedOwnerAccount(t, "owner-1", 10)

	// Act
	w := postInvite(t, h, accountID, "owner-1", `{"email":"invitee@example.com"}`)

	// Assert
	if w.Code != stdhttp.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["invite_id"] == "" {
		t.Errorf("expected non-empty invite_id, got %v", resp["invite_id"])
	}
	if resp["invited_email"] != "invitee@example.com" {
		t.Errorf("invited_email = %v, want invitee@example.com", resp["invited_email"])
	}
	// Raw token MUST NOT appear in the response body — it's emailed
	// only. The test asserts this negatively.
	if _, present := resp["token"]; present {
		t.Error("token must not be in response body — only emailed")
	}
}

func TestCreateInvite_403WhenNotOwner(t *testing.T) {
	// Arrange
	h, accountID := seedOwnerAccount(t, "owner-1", 10)

	// Act — requester is a random user, not an owner-seat
	w := postInvite(t, h, accountID, "not-owner", `{"email":"invitee@example.com"}`)

	// Assert
	if w.Code != stdhttp.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestCreateInvite_409WhenSeatLimitReached(t *testing.T) {
	// Arrange — personal-account default allowance = 1; owner
	// already occupies it, so any invite would exceed.
	h, accountID := seedOwnerAccount(t, "owner-1", 1)

	// Act
	w := postInvite(t, h, accountID, "owner-1", `{"email":"invitee@example.com"}`)

	// Assert
	if w.Code != stdhttp.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestCreateInvite_400OnMissingEmail(t *testing.T) {
	// Arrange
	h, accountID := seedOwnerAccount(t, "owner-1", 10)

	// Act
	w := postInvite(t, h, accountID, "owner-1", `{}`)

	// Assert
	if w.Code != stdhttp.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateInvite_400OnMissingRequesterHeader(t *testing.T) {
	// Arrange — no X-Requester-User-ID header. Without a requester
	// identity there's no way to run the owner-check, so this is a
	// wire-shape failure not a 403.
	h, accountID := seedOwnerAccount(t, "owner-1", 10)

	// Act
	w := postInvite(t, h, accountID, "", `{"email":"invitee@example.com"}`)

	// Assert
	if w.Code != stdhttp.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateInvite_400OnMalformedJSON(t *testing.T) {
	// Arrange
	h, accountID := seedOwnerAccount(t, "owner-1", 10)

	// Act
	w := postInvite(t, h, accountID, "owner-1", `{not-json`)

	// Assert
	if w.Code != stdhttp.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
