package http_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// --- fakes for the account switcher ---

type fakeSeatLister struct {
	mu      sync.Mutex
	gotUser string
	seats   []ports.AccountSeat
	err     error
	callN   int
}

func (f *fakeSeatLister) ListUserSeats(_ context.Context, userID string) ([]ports.AccountSeat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotUser = userID
	f.callN++
	return f.seats, f.err
}

type fakeActiveAccount struct {
	mu           sync.Mutex
	getResp      string
	getErr       error
	setErr       error
	setUser      string
	setAccountID string
	setCalls     int
}

func (f *fakeActiveAccount) GetActiveAccount(_ context.Context, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getResp, f.getErr
}

func (f *fakeActiveAccount) SetActiveAccount(_ context.Context, userID, accountID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setUser = userID
	f.setAccountID = accountID
	f.setCalls++
	return f.setErr
}

func newAccountsHandler(seats *fakeSeatLister, active *fakeActiveAccount) *authhttp.Handler {
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(nil, nil, logger).WithAccounts(seats, active)
}

// --- AccountsGet ---

func TestAccountsGet_Returns503WhenUnwired(t *testing.T) {
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger)

	req := httptest.NewRequest(http.MethodGet, "/accounts?subject=u-1", nil)
	w := httptest.NewRecorder()
	h.AccountsGet(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestAccountsGet_Returns400WhenSubjectMissing(t *testing.T) {
	h := newAccountsHandler(&fakeSeatLister{}, &fakeActiveAccount{})
	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	w := httptest.NewRecorder()

	h.AccountsGet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAccountsGet_RendersEmptyState(t *testing.T) {
	h := newAccountsHandler(&fakeSeatLister{seats: nil}, &fakeActiveAccount{})
	req := httptest.NewRequest(http.MethodGet, "/accounts?subject=u-nobody", nil)
	w := httptest.NewRecorder()

	h.AccountsGet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "don't have any accounts") {
		t.Errorf("expected empty-state text; body = %s", w.Body.String())
	}
}

func TestAccountsGet_RendersSingleAccountView(t *testing.T) {
	seats := &fakeSeatLister{seats: []ports.AccountSeat{
		{SeatID: "s1", AccountID: "a1", AccountDisplayName: "Personal", Role: "owner"},
	}}
	h := newAccountsHandler(seats, &fakeActiveAccount{getResp: "a1"})
	req := httptest.NewRequest(http.MethodGet, "/accounts?subject=u-solo", nil)
	w := httptest.NewRecorder()

	h.AccountsGet(w, req)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(body, "Only account") {
		t.Errorf("expected 'Only account' marker in single-account view; body = %s", body)
	}
	// Single-account view must NOT render a switch button.
	if strings.Contains(body, "Switch to this account") {
		t.Errorf("single-account view should not offer a switch button")
	}
}

func TestAccountsGet_RendersSwitcherForMultipleSeats(t *testing.T) {
	seats := &fakeSeatLister{seats: []ports.AccountSeat{
		{SeatID: "s1", AccountID: "a1", AccountDisplayName: "Personal", Role: "owner"},
		{SeatID: "s2", AccountID: "a2", AccountDisplayName: "Club", Role: "member", PlanName: "Touchline Club"},
	}}
	active := &fakeActiveAccount{getResp: "a1"}
	h := newAccountsHandler(seats, active)

	req := httptest.NewRequest(http.MethodGet, "/accounts?subject=u-1", nil)
	w := httptest.NewRecorder()
	h.AccountsGet(w, req)

	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	assertSwitcherBody(t, body)
	if seats.gotUser != "u-1" {
		t.Errorf("seats fetcher user = %q, want u-1", seats.gotUser)
	}
}

// assertSwitcherBody keeps TestAccountsGet_RendersSwitcherForMultipleSeats
// under the gocyclo cap while covering every visible branch of the
// template's multi-seat render.
func assertSwitcherBody(t *testing.T, body string) {
	t.Helper()
	if !strings.Contains(body, "Personal") || !strings.Contains(body, "Club") {
		t.Errorf("expected both accounts in body; body = %s", body)
	}
	if !strings.Contains(body, "Touchline Club") {
		t.Errorf("expected plan name for second seat; body = %s", body)
	}
	if !strings.Contains(body, "Current") {
		t.Errorf("expected 'Current' marker on active account; body = %s", body)
	}
	if !strings.Contains(body, "Switch to this account") {
		t.Errorf("expected switch button on non-active account; body = %s", body)
	}
}

func TestAccountsGet_RendersChangedNotice(t *testing.T) {
	h := newAccountsHandler(&fakeSeatLister{}, &fakeActiveAccount{})
	req := httptest.NewRequest(http.MethodGet, "/accounts?subject=u-1&changed=1", nil)
	w := httptest.NewRecorder()

	h.AccountsGet(w, req)
	if !strings.Contains(w.Body.String(), "Active account updated") {
		t.Errorf("expected changed-notice banner; body = %s", w.Body.String())
	}
}

// --- AccountsPost ---

func postSwitch(subject, accountID string) *http.Request {
	body := strings.NewReader("active_account_id=" + accountID)
	r := httptest.NewRequest(http.MethodPost, "/accounts?subject="+subject, body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestAccountsPost_Success_RedirectsWithChangedFlag(t *testing.T) {
	active := &fakeActiveAccount{}
	h := newAccountsHandler(&fakeSeatLister{}, active)

	w := httptest.NewRecorder()
	h.AccountsPost(w, postSwitch("u-1", "a-new"))

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/accounts?subject=u-1&changed=1" {
		t.Errorf("Location = %q, want /accounts?subject=u-1&changed=1", got)
	}
	if active.setUser != "u-1" || active.setAccountID != "a-new" {
		t.Errorf("active setter called with (%q, %q), want (u-1, a-new)", active.setUser, active.setAccountID)
	}
}

func TestAccountsPost_MissingSubject_Returns400(t *testing.T) {
	h := newAccountsHandler(&fakeSeatLister{}, &fakeActiveAccount{})
	r := httptest.NewRequest(http.MethodPost, "/accounts", strings.NewReader("active_account_id=a"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.AccountsPost(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAccountsPost_MissingAccountID_Returns400(t *testing.T) {
	h := newAccountsHandler(&fakeSeatLister{}, &fakeActiveAccount{})
	r := httptest.NewRequest(http.MethodPost, "/accounts?subject=u-1", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.AccountsPost(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAccountsPost_SetterErrorRendersInlineBanner(t *testing.T) {
	active := &fakeActiveAccount{setErr: errFakeSetterFailure}
	h := newAccountsHandler(&fakeSeatLister{}, active)

	w := httptest.NewRecorder()
	h.AccountsPost(w, postSwitch("u-1", "a-new"))

	// Non-fatal: re-render the page with an inline error, NOT a 5xx.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inline error render)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Could not switch account") {
		t.Errorf("expected inline error banner; body = %s", w.Body.String())
	}
}

var errFakeSetterFailure = &fakeError{msg: "identity-service down"}

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }
