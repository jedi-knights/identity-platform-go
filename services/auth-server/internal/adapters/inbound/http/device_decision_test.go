//go:build unit

package http_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func postDeviceDecisionJSON(h *authhttp.DeviceAuthorizationHandler, body []byte, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/internal/device/decision", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.PostDecision(w, r)
	return w
}

func TestDeviceAuthorizationHandler_PostDecision_Approve(t *testing.T) {
	// Arrange
	repo := &fakeDeviceAuthRepo{}
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}, repo)
	body, _ := json.Marshal(map[string]any{
		"user_code": "ABCD-1234",
		"subject":   "user-42",
		"approved":  true,
	})

	// Act
	w := postDeviceDecisionJSON(h, body, testDeviceServiceToken)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if repo.approvedUserCode != "ABCD-1234" || repo.approvedSubject != "user-42" {
		t.Errorf("repo.Approve called with (%q, %q), want (ABCD-1234, user-42)", repo.approvedUserCode, repo.approvedSubject)
	}
}

func TestDeviceAuthorizationHandler_PostDecision_Deny(t *testing.T) {
	// Arrange
	repo := &fakeDeviceAuthRepo{}
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}, repo)
	body, _ := json.Marshal(map[string]any{
		"user_code": "WXYZ-5678",
		"approved":  false,
	})

	// Act
	w := postDeviceDecisionJSON(h, body, testDeviceServiceToken)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if repo.deniedUserCode != "WXYZ-5678" {
		t.Errorf("repo.Deny called with %q, want WXYZ-5678", repo.deniedUserCode)
	}
}

func TestDeviceAuthorizationHandler_PostDecision_WrongBearerToken(t *testing.T) {
	// Arrange
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}, &fakeDeviceAuthRepo{})
	body, _ := json.Marshal(map[string]any{"user_code": "ABCD-1234", "approved": true})

	// Act
	w := postDeviceDecisionJSON(h, body, "wrong-token")

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestDeviceAuthorizationHandler_PostDecision_MissingBearerToken(t *testing.T) {
	// Arrange
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}, &fakeDeviceAuthRepo{})
	body, _ := json.Marshal(map[string]any{"user_code": "ABCD-1234", "approved": true})

	// Act
	w := postDeviceDecisionJSON(h, body, "")

	// Assert
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestDeviceAuthorizationHandler_PostDecision_MissingUserCode(t *testing.T) {
	// Arrange
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}, &fakeDeviceAuthRepo{})
	body, _ := json.Marshal(map[string]any{"approved": true})

	// Act
	w := postDeviceDecisionJSON(h, body, testDeviceServiceToken)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDeviceAuthorizationHandler_PostDecision_UnknownUserCode(t *testing.T) {
	// Arrange — Approve returns ErrDeviceAuthorizationNotFound by default
	// on fakeDeviceAuthRepo only when configured; simulate via approveErr.
	repo := &fakeDeviceAuthRepo{approveErr: domain.ErrDeviceAuthorizationNotFound}
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}, repo)
	body, _ := json.Marshal(map[string]any{"user_code": "NEVER-SAVED", "subject": "user-1", "approved": true})

	// Act
	w := postDeviceDecisionJSON(h, body, testDeviceServiceToken)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestDeviceAuthorizationHandler_PostDecision_ApproveMissingSubject(t *testing.T) {
	// Arrange — approving without identifying who approved is a caller bug.
	h := newTestDeviceAuthorizationHandler(&fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}, &fakeDeviceAuthRepo{})
	body, _ := json.Marshal(map[string]any{"user_code": "ABCD-1234", "approved": true})

	// Act
	w := postDeviceDecisionJSON(h, body, testDeviceServiceToken)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
