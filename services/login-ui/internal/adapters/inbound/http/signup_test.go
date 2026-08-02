package http_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"

	authhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// fakeRegistrar records the last Register call so tests can assert
// the handler forwards form fields correctly, and returns a canned
// result / error so failure branches are exercisable without a real
// identity-service.
type fakeRegistrar struct {
	mu     sync.Mutex
	gotReq ports.RegisterRequest
	resp   *ports.RegisterResult
	err    error
}

func (f *fakeRegistrar) Register(_ context.Context, req ports.RegisterRequest) (*ports.RegisterResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func newSignUpHandler(reg *fakeRegistrar) *authhttp.Handler {
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(nil, nil, logger).WithRegistrar(reg)
}

func postSignUp(name, email, password string) *http.Request {
	body := strings.NewReader("name=" + name + "&email=" + email + "&password=" + password)
	r := httptest.NewRequest(http.MethodPost, "/sign-up", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// --- GET /sign-up ---

func TestSignUpGet_Returns503WhenUnwired(t *testing.T) {
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger)

	r := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
	w := httptest.NewRecorder()
	h.SignUpGet(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestSignUpGet_RendersForm(t *testing.T) {
	h := newSignUpHandler(&fakeRegistrar{})

	r := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
	w := httptest.NewRecorder()
	h.SignUpGet(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `action="/sign-up"`) {
		t.Errorf("body missing sign-up form action; body = %s", body)
	}
	if !strings.Contains(body, `name="email"`) {
		t.Errorf("body missing email input; body = %s", body)
	}
}

// --- POST /sign-up ---

func TestSignUpPost_Success_RedirectsToPlansWithSubject(t *testing.T) {
	reg := &fakeRegistrar{resp: &ports.RegisterResult{UserID: "u-new-42", Email: "alice@example.com", Name: "Alice"}}
	h := newSignUpHandler(reg)

	w := httptest.NewRecorder()
	h.SignUpPost(w, postSignUp("Alice", "alice@example.com", "hunter2"))

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/billing/plans?subject=u-new-42" {
		t.Errorf("Location = %q, want /billing/plans?subject=u-new-42", loc)
	}
	if reg.gotReq.Email != "alice@example.com" || reg.gotReq.Name != "Alice" || reg.gotReq.Password != "hunter2" {
		t.Errorf("registrar received %+v, want the form values verbatim", reg.gotReq)
	}
}

func TestSignUpPost_Success_IncludesAccountIDWhenPresent(t *testing.T) {
	reg := &fakeRegistrar{resp: &ports.RegisterResult{
		UserID:    "u-new-42",
		Email:     "alice@example.com",
		Name:      "Alice",
		AccountID: "acc-99",
	}}
	h := newSignUpHandler(reg)

	w := httptest.NewRecorder()
	h.SignUpPost(w, postSignUp("Alice", "alice@example.com", "hunter2"))

	// url.Values.Encode sorts keys alphabetically — the order is
	// semantically identical to subject=...&account=...; assert on the
	// individual parameters rather than the literal string.
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "subject=u-new-42") || !strings.Contains(loc, "account=acc-99") {
		t.Errorf("Location = %q missing subject/account params", loc)
	}
}

func TestSignUpPost_MissingFields_InlineError200(t *testing.T) {
	h := newSignUpHandler(&fakeRegistrar{})

	w := httptest.NewRecorder()
	h.SignUpPost(w, postSignUp("", "alice@example.com", "hunter2"))

	// Missing field surfaces as a re-rendered form (200), not a 5xx —
	// the user corrects and retries in place.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inline error render)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "all required") {
		t.Errorf("expected inline error banner; body = %s", w.Body.String())
	}
}

func TestSignUpPost_DuplicateEmail_ConflictErrorRendered(t *testing.T) {
	reg := &fakeRegistrar{err: apperrors.New(apperrors.ErrCodeConflict, "email already registered")}
	h := newSignUpHandler(reg)

	w := httptest.NewRecorder()
	h.SignUpPost(w, postSignUp("Alice", "alice@example.com", "hunter2"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inline error render)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("expected conflict-specific error; body = %s", w.Body.String())
	}
}

func TestSignUpPost_UpstreamFailure_GenericErrorRendered(t *testing.T) {
	reg := &fakeRegistrar{err: errors.New("identity-service unavailable")}
	h := newSignUpHandler(reg)

	w := httptest.NewRecorder()
	h.SignUpPost(w, postSignUp("Alice", "alice@example.com", "hunter2"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inline error render)", w.Code)
	}
	// Generic banner — must NOT surface the upstream message verbatim.
	// Substring dodges the HTML-escaped apostrophe in "couldn't".
	if !strings.Contains(w.Body.String(), "create your account. Please try again.") {
		t.Errorf("expected generic error banner; body = %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "identity-service unavailable") {
		t.Errorf("upstream error leaked to user; body = %s", w.Body.String())
	}
}

func TestSignUpPost_PreservesNameAndEmailOnError(t *testing.T) {
	reg := &fakeRegistrar{err: apperrors.New(apperrors.ErrCodeConflict, "dup")}
	h := newSignUpHandler(reg)

	w := httptest.NewRecorder()
	h.SignUpPost(w, postSignUp("Alice", "alice@example.com", "hunter2"))

	body := w.Body.String()
	if !strings.Contains(body, `value="Alice"`) || !strings.Contains(body, `value="alice@example.com"`) {
		t.Errorf("re-rendered form must preserve name + email; body = %s", body)
	}
}

// --- routes reachable via NewRouter ---

func TestNewRouter_SignUpRoutesReachable(t *testing.T) {
	reg := &fakeRegistrar{resp: &ports.RegisterResult{UserID: "u-1"}}
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger).WithRegistrar(reg)
	router := authhttp.NewRouter(h, logger)

	// GET
	req := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /sign-up via router: status = %d, want 200", w.Code)
	}

	// POST
	req = httptest.NewRequest(http.MethodPost, "/sign-up",
		strings.NewReader("name=Alice&email=a@x.com&password=hunter2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("POST /sign-up via router: status = %d, want 302", w.Code)
	}
}
