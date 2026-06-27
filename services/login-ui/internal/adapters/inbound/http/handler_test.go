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
	"github.com/jedi-knights/go-platform/audit"

	authhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// --- fakes ---

type fakeUserAuth struct {
	mu       sync.Mutex
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
	mu     sync.Mutex
	gotReq ports.IssueCodeRequest
	resp   *ports.IssueCodeResponse
	err    error
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
	assertSignInHappyPath(t, w, ua, ci)
}

// assertSignInHappyPath verifies the happy-path SignInPost response.
// Delegated to two helpers so each one stays within the project's
// cyclomatic-complexity cap of 7.
func assertSignInHappyPath(t *testing.T, w *httptest.ResponseRecorder, ua *fakeUserAuth, ci *fakeCodeIssuer) {
	t.Helper()
	assertSignInRedirect(t, w)
	assertSignInPropagation(t, ua, ci)
}

// assertSignInRedirect checks the 302 Location and its query parameters.
func assertSignInRedirect(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
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
}

// assertSignInPropagation checks that the form input was forwarded to
// VerifyCredentials and the resolved subject was forwarded to IssueCode.
func assertSignInPropagation(t *testing.T, ua *fakeUserAuth, ci *fakeCodeIssuer) {
	t.Helper()
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

// --- Audit emission (ADR-0018 / ADR-0019) ---

type captureSink struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (c *captureSink) Sink(_ context.Context, e audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return c.err
}

func (c *captureSink) snapshot() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

var errAuditFailure = errors.New("simulated audit transport failure")

func TestSignInPost_EmitsSigninCompleted(t *testing.T) {
	ua := &fakeUserAuth{subject: "user-42"}
	ci := &fakeCodeIssuer{resp: &ports.IssueCodeResponse{
		Code:        "auth-code-xyz",
		RedirectURI: "https://rp.example.com/callback",
		State:       "rp-state",
	}}
	sink := &captureSink{}
	h := newSignInHandler(t, ua, ci).WithAudit(audit.New(sink), "login-ui")

	w := postSignIn(t, h, url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"hunter2"},
	})
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	e := events[0]
	if e.EventType != "signin_completed" {
		t.Errorf("event_type = %q, want signin_completed", e.EventType)
	}
	if e.Service != "login-ui" {
		t.Errorf("service = %q, want login-ui", e.Service)
	}
	if e.ActorType != audit.ActorTypeUser {
		t.Errorf("actor_type = %q, want user", e.ActorType)
	}
	if e.ActorID != "user-42" {
		t.Errorf("actor_id = %q, want user-42", e.ActorID)
	}
	if e.SubjectID != "user-42" {
		t.Errorf("subject_id = %q, want user-42", e.SubjectID)
	}
	if e.ResourceKind != audit.ResourceKindApplication {
		t.Errorf("resource_kind = %q, want application", e.ResourceKind)
	}
	if e.ResourcePath != "login-ui/application/signin" {
		t.Errorf("resource_path = %q, want login-ui/application/signin", e.ResourcePath)
	}
	if ch, _ := e.Attrs["login_challenge"].(string); ch != "ch-1" {
		t.Errorf("attrs.login_challenge = %v, want ch-1", e.Attrs["login_challenge"])
	}
}

func TestSignInPost_BadCredentialsDoesNotEmit(t *testing.T) {
	// Failed sign-ins belong on a security-audit stream — not on the
	// billing stream emitted here.
	ua := &fakeUserAuth{err: apperrors.New(apperrors.ErrCodeUnauthorized, "bad password")}
	ci := &fakeCodeIssuer{}
	sink := &captureSink{}
	h := newSignInHandler(t, ua, ci).WithAudit(audit.New(sink), "login-ui")

	_ = postSignIn(t, h, url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"wrong"},
	})
	if len(sink.snapshot()) != 0 {
		t.Errorf("expected no audit event on failed sign-in, got %d", len(sink.snapshot()))
	}
}

func TestSignInPost_IssueCodeFailureDoesNotEmit(t *testing.T) {
	ua := &fakeUserAuth{subject: "user-42"}
	ci := &fakeCodeIssuer{err: errors.New("auth-server unreachable")}
	sink := &captureSink{}
	h := newSignInHandler(t, ua, ci).WithAudit(audit.New(sink), "login-ui")

	_ = postSignIn(t, h, url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"hunter2"},
	})
	if len(sink.snapshot()) != 0 {
		t.Errorf("expected no audit event when issue-code fails, got %d", len(sink.snapshot()))
	}
}

func TestSignInPost_AuditFailureDegradesGracefully(t *testing.T) {
	// Per ADR-0019: a durable-sink failure must not leave the user with a
	// half-completed sign-in. The handler re-renders the form with a
	// generic error rather than emitting the redirect.
	ua := &fakeUserAuth{subject: "user-42"}
	ci := &fakeCodeIssuer{resp: &ports.IssueCodeResponse{
		Code:        "auth-code-xyz",
		RedirectURI: "https://rp.example.com/callback",
		State:       "rp-state",
	}}
	sink := &captureSink{err: errAuditFailure}
	h := newSignInHandler(t, ua, ci).WithAudit(audit.New(sink), "login-ui")

	w := postSignIn(t, h, url.Values{
		"login_challenge": {"ch-1"},
		"email":           {"user@example.com"},
		"password":        {"hunter2"},
	})
	if w.Code == http.StatusFound {
		t.Errorf("expected no redirect when audit emit fails, got 302")
	}
	if !strings.Contains(w.Body.String(), "could not complete sign-in") {
		t.Errorf("expected generic error in body, got: %s", w.Body.String())
	}
}

func TestHandler_WithAudit_NilEmitterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = newSignInHandler(t, &fakeUserAuth{}, &fakeCodeIssuer{}).WithAudit(nil, "login-ui")
}
