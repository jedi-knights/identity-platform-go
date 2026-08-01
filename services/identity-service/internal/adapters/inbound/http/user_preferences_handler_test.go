package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/testutil"
)

func newActiveAccountHandler(prefs *fakePreferences) *Handler {
	return NewHandler(
		&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{},
		&fakeClaims{}, prefs,
		testutil.NewTestLogger(),
	)
}

// --- GET /users/{id}/active-account ---

func TestGetActiveAccount_ReturnsAccountID(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{getResp: "acc-1"})
	r := httptest.NewRequest(http.MethodGet, "/users/u-1/active-account", nil)
	r.SetPathValue("id", "u-1")
	r.Header.Set(requesterHeader, "u-1")
	w := httptest.NewRecorder()

	h.GetActiveAccount(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body activeAccountResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.AccountID == nil || *body.AccountID != "acc-1" {
		t.Errorf("account_id = %+v, want acc-1", body.AccountID)
	}
}

func TestGetActiveAccount_NullWhenNotSet(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{getResp: ""})
	r := httptest.NewRequest(http.MethodGet, "/users/u-1/active-account", nil)
	r.SetPathValue("id", "u-1")
	r.Header.Set(requesterHeader, "u-1")
	w := httptest.NewRecorder()

	h.GetActiveAccount(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"account_id":null`) {
		t.Errorf("body = %s, want account_id:null", w.Body.String())
	}
}

func TestGetActiveAccount_MissingHeader_Returns400(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{})
	r := httptest.NewRequest(http.MethodGet, "/users/u-1/active-account", nil)
	r.SetPathValue("id", "u-1")
	w := httptest.NewRecorder()

	h.GetActiveAccount(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetActiveAccount_RequesterMismatch_Returns403(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{})
	r := httptest.NewRequest(http.MethodGet, "/users/u-1/active-account", nil)
	r.SetPathValue("id", "u-1")
	r.Header.Set(requesterHeader, "u-99")
	w := httptest.NewRecorder()

	h.GetActiveAccount(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// --- PUT /users/{id}/active-account ---

func putActiveAccount(t *testing.T, h *Handler, userID, requester string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	r := httptest.NewRequest(http.MethodPut, "/users/"+userID+"/active-account", bytes.NewReader(b))
	r.SetPathValue("id", userID)
	if requester != "" {
		r.Header.Set(requesterHeader, requester)
	}
	w := httptest.NewRecorder()
	h.SetActiveAccount(w, r)
	return w
}

func TestSetActiveAccount_Success_Returns204(t *testing.T) {
	prefs := &fakePreferences{}
	h := newActiveAccountHandler(prefs)

	w := putActiveAccount(t, h, "u-1", "u-1", setActiveAccountRequest{AccountID: "acc-1"})

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
}

func TestSetActiveAccount_MissingHeader_Returns400(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{})
	w := putActiveAccount(t, h, "u-1", "", setActiveAccountRequest{AccountID: "acc-1"})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSetActiveAccount_RequesterMismatch_Returns403(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{})
	w := putActiveAccount(t, h, "u-1", "u-99", setActiveAccountRequest{AccountID: "acc-1"})

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestSetActiveAccount_MalformedJSON_Returns400(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{})
	r := httptest.NewRequest(http.MethodPut, "/users/u-1/active-account", strings.NewReader("not-json"))
	r.SetPathValue("id", "u-1")
	r.Header.Set(requesterHeader, "u-1")
	w := httptest.NewRecorder()

	h.SetActiveAccount(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSetActiveAccount_EmptyAccountID_Returns400(t *testing.T) {
	h := newActiveAccountHandler(&fakePreferences{
		setErr: apperrors.New(apperrors.ErrCodeBadRequest, "account id is required"),
	})
	w := putActiveAccount(t, h, "u-1", "u-1", setActiveAccountRequest{AccountID: ""})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
