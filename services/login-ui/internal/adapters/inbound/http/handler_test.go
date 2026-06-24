package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"

	authhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// --- fakes ---

type fakeUserAuth struct {
	mu      sync.Mutex
	gotEmail string
	gotPass  string
	subject  string
	err      error
}

func (f *fakeUserAuth) VerifyCredentials(_ context.Context, email, password string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotEmail = email
	f.gotPass = password
	if f.err != nil {
		return "", f.err
	}
	return f.subject, nil
}

type fakeCodeIssuer struct {
	mu      sync.Mutex
	gotReq  ports.IssueCodeRequest
	resp    *ports.IssueCodeResponse
	err     error
}

func (f *fakeCodeIssuer) IssueCode(_ context.Context, req ports.IssueCodeRequest) (*ports.IssueCodeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// --- helpers ---

func newSignInHandler(t *testing.T, ua *fakeUserAuth, ci *fakeCodeIssuer) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(ua, ci, logger)
}

func newDegradedHandler(t *testing.T) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(nil, nil, logger)
}

// --- /health ---

func TestHealth_Returns200WithStatusOK(t *testing.T) {
	// Arrange — /health must work regardless of whether the sign-in
	// dependencies are wired (it is the docker-compose liveness probe).
	h := newDegradedHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	// Act
	h.Health(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want %q", body["status"], "ok")
	}
}

// --- GET /sign-in ---

func TestSignInGet_RendersFormWithLoginChallengeHidden(t *testing.T) {
	// Arrange
	h := newSignInHandler(t, &fakeUserAuth{}, &fakeCodeIssuer{})
	r := httptest.NewRequest(http.MethodGet, "/sign-in?login_challenge=ch-1", nil)
	w := httptest.NewRecorder()

	// Act
	h.SignInGet(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="login_challenge"`) || !strings.Contains(body, `value="ch-1"`) {
		t.Errorf("hidden login_challenge not rendered; body = %q", body)
	}
	if !strings.Contains(body, `method="POST"`) || !strings.Contains(body, `action="/sign-in"`) {
		t.Errorf("form attrs missing; body = %q", body)
	}
}

func TestSignInGet_MissingChallenge_Returns400(t *testing.T) {
	// Arrange
	h := newSignInHandler(t, &fakeUserAuth{}, &fakeCodeIssuer{})
	r := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
	w := httptest.NewRecorder()

	// Act
	h.SignInGet(w, r)

	// Assert
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSignInGet_Degraded_Returns503(t *testing.T) {
	// Arrange — without outbound dependencies the sign-in flow cannot
	// proceed; return 503 rather than rendering a form the user cannot
	// submit.
	h := newDegradedHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/sign-in?login_challenge=ch-1", nil)
	w := httptest.NewRecorder()

	// Act
	h.SignInGet(w, r)

	// Assert
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

// --- POST /sign-in ---

func postSignIn(t *testing.T, h *authhttp.Handler, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/sign-in", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.SignInPost(w, r)
	return w
}

func TestSignInPost_HappyPath_RedirectsToRPWithCodeAndState(t *testing.T) {
	// Arrange
	ua := &fakeUserAuth{subject: "user-42"}
	ci := &fakeCodeIssuer{resp: &ports.IssueCodeResponse{
		Code:        "code-xyz",
		RedirectURI: "https://rp.example.com/cb",
		State:       "state-abc",
	}}
	h := newSignInHandler(t, ua, ci)
	values := url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"hunter2"},
	}

	// Act
	w := postSignIn(t, h, values)

	// Assert
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	if parsed.Host != "rp.example.com" || parsed.Path != "/cb" {
		t.Errorf("redirected to %q, want https://rp.example.com/cb", loc)
	}
	if got := parsed.Query().Get("code"); got != "code-xyz" {
		t.Errorf("code query = %q, want code-xyz", got)
	}
	if got := parsed.Query().Get("state"); got != "state-abc" {
		t.Errorf("state query = %q, want state-abc", got)
	}
	if ua.gotEmail != "user@example.com" {
		t.Errorf("VerifyCredentials email = %q", ua.gotEmail)
	}
	if ci.gotReq.LoginChallenge != "ch-1" || ci.gotReq.SessionID != "user-42" {
		t.Errorf("IssueCode req = %+v", ci.gotReq)
	}
}

func TestSignInPost_BadCredentials_RendersFormWithError(t *testing.T) {
	// Arrange
	ua := &fakeUserAuth{err: apperrors.New(apperrors.ErrCodeUnauthorized, "bad password")}
	ci := &fakeCodeIssuer{}
	h := newSignInHandler(t, ua, ci)
	values := url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"wrong"},
	}

	// Act
	w := postSignIn(t, h, values)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (form re-render)", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "invalid email or password") {
		t.Errorf("error message missing; body = %q", body)
	}
	if !strings.Contains(body, `value="ch-1"`) {
		t.Error("login_challenge lost on form re-render")
	}
}

func TestSignInPost_MissingFields_RendersFormWithError(t *testing.T) {
	// Arrange
	h := newSignInHandler(t, &fakeUserAuth{}, &fakeCodeIssuer{})
	values := url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		// password missing
	}

	// Act
	w := postSignIn(t, h, values)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (form re-render)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "required") {
		t.Errorf("required-fields message missing; body = %q", w.Body.String())
	}
}

func TestSignInPost_IssueCodeFails_RendersGenericError(t *testing.T) {
	// Arrange — credentials accepted but auth-server /internal/issue-code
	// returns an error (expired challenge, network failure, etc.). The
	// user is shown a generic message and the form is re-rendered so they
	// can try a new flow.
	ua := &fakeUserAuth{subject: "user-42"}
	ci := &fakeCodeIssuer{err: errors.New("auth-server unavailable")}
	h := newSignInHandler(t, ua, ci)
	values := url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"hunter2"},
	}

	// Act
	w := postSignIn(t, h, values)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (form re-render)", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "could not complete sign-in") {
		t.Errorf("generic error missing; body = %q", body)
	}
}

func TestSignInPost_Degraded_Returns503(t *testing.T) {
	// Arrange
	h := newDegradedHandler(t)
	values := url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"hunter2"},
	}

	// Act
	w := postSignIn(t, h, values)

	// Assert
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}
