package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/testutil"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// --- fakes ---

type fakeAuthenticator struct {
	resp *domain.LoginResponse
	err  error
}

func (f *fakeAuthenticator) Login(_ context.Context, _ domain.LoginRequest) (*domain.LoginResponse, error) {
	return f.resp, f.err
}

type fakeRegistrar struct {
	resp *domain.RegisterResponse
	err  error
}

func (f *fakeRegistrar) Register(_ context.Context, _ domain.RegisterRequest) (*domain.RegisterResponse, error) {
	return f.resp, f.err
}

// fakeClaims is the test double for ports.UserClaimsProvider — returns the
// canned response or err verbatim.
type fakeClaims struct {
	resp *domain.UserClaims
	err  error
}

func (f *fakeClaims) GetUserClaims(_ context.Context, _ string) (*domain.UserClaims, error) {
	return f.resp, f.err
}

type fakeVerifier struct {
	requestErr error
	verifyResp *domain.VerifyEmailResponse
	verifyErr  error
}

func (f *fakeVerifier) RequestVerification(_ context.Context, _ domain.RequestVerificationRequest) error {
	return f.requestErr
}

func (f *fakeVerifier) VerifyEmail(_ context.Context, _ domain.VerifyEmailRequest) (*domain.VerifyEmailResponse, error) {
	return f.verifyResp, f.verifyErr
}

// spyLogger wraps a no-op logger and records whether Error was called.
type spyLogger struct {
	logging.Logger
	errorCalled bool
}

func (s *spyLogger) Error(_ string, _ ...any) { s.errorCalled = true }

// --- helpers ---

func postJSON(t *testing.T, h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// --- Login ---

func TestLogin_Success_Returns200(t *testing.T) {
	auth := &fakeAuthenticator{resp: &domain.LoginResponse{UserID: "u1", Email: "a@b.com", Name: "Alice"}}
	h := NewHandler(auth, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())

	w := postJSON(t, h.Login, domain.LoginRequest{Email: "a@b.com", Password: "secret"})
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	var resp domain.LoginResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.UserID != "u1" {
		t.Errorf("UserID: got %q, want %q", resp.UserID, "u1")
	}
}

func TestLogin_InvalidCredentials_Returns401(t *testing.T) {
	auth := &fakeAuthenticator{err: apperrors.New(apperrors.ErrCodeUnauthorized, "invalid credentials")}
	h := NewHandler(auth, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())

	w := postJSON(t, h.Login, domain.LoginRequest{Email: "a@b.com", Password: "wrong"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLogin_BadJSON_Returns400(t *testing.T) {
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestLogin_DoesNotLogNonInternalErrors verifies the conditional logging gate:
// known errors (401, 403, 409) must not be logged at Error level.
func TestLogin_DoesNotLogNonInternalErrors(t *testing.T) {
	spy := &spyLogger{Logger: testutil.NewTestLogger()}
	auth := &fakeAuthenticator{err: apperrors.New(apperrors.ErrCodeUnauthorized, "invalid")}
	h := NewHandler(auth, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, spy)

	postJSON(t, h.Login, domain.LoginRequest{Email: "a@b.com", Password: "wrong"})
	if spy.errorCalled {
		t.Error("logger.Error must not be called for non-internal errors")
	}
}

// --- Register ---

func TestRegister_Success_Returns201WithLocation(t *testing.T) {
	reg := &fakeRegistrar{resp: &domain.RegisterResponse{UserID: "u2", Email: "b@b.com", Name: "Bob"}}
	h := NewHandler(&fakeAuthenticator{}, reg, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())

	w := postJSON(t, h.Register, domain.RegisterRequest{Email: "b@b.com", Password: "pass", Name: "Bob"})
	if w.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d — body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/users/u2" {
		t.Errorf("Location: got %q, want %q", loc, "/users/u2")
	}
}

func TestRegister_DuplicateEmail_Returns409(t *testing.T) {
	reg := &fakeRegistrar{err: apperrors.New(apperrors.ErrCodeConflict, "email already registered")}
	h := NewHandler(&fakeAuthenticator{}, reg, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())

	w := postJSON(t, h.Register, domain.RegisterRequest{Email: "b@b.com", Password: "pass", Name: "Bob"})
	if w.Code != http.StatusConflict {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestRegister_BadJSON_Returns400(t *testing.T) {
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	h.Register(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestRegister_DoesNotLogNonInternalErrors verifies the conditional logging gate
// added to Register: conflict/bad-request errors must not flood the error log.
func TestRegister_DoesNotLogNonInternalErrors(t *testing.T) {
	spy := &spyLogger{Logger: testutil.NewTestLogger()}
	reg := &fakeRegistrar{err: apperrors.New(apperrors.ErrCodeConflict, "email already registered")}
	h := NewHandler(&fakeAuthenticator{}, reg, &fakeVerifier{}, &fakeClaims{}, spy)

	postJSON(t, h.Register, domain.RegisterRequest{Email: "b@b.com", Password: "pass", Name: "Bob"})
	if spy.errorCalled {
		t.Error("logger.Error must not be called for ErrCodeConflict")
	}
}

// TestRegister_LogsInternalErrors verifies that genuine infrastructure failures
// are still logged at Error level.
func TestRegister_LogsInternalErrors(t *testing.T) {
	spy := &spyLogger{Logger: testutil.NewTestLogger()}
	reg := &fakeRegistrar{err: apperrors.New(apperrors.ErrCodeInternal, "db down")}
	h := NewHandler(&fakeAuthenticator{}, reg, &fakeVerifier{}, &fakeClaims{}, spy)

	postJSON(t, h.Register, domain.RegisterRequest{Email: "b@b.com", Password: "pass", Name: "Bob"})
	if !spy.errorCalled {
		t.Error("logger.Error must be called for internal errors")
	}
}

// --- GetUserClaims ---

func TestGetUserClaims_Success_Returns200(t *testing.T) {
	claims := &fakeClaims{resp: &domain.UserClaims{
		Subject: "u-1", Email: "alice@example.com", EmailVerified: true, Name: "Alice",
	}}
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, claims, testutil.NewTestLogger())

	r := httptest.NewRequest(http.MethodGet, "/users/u-1/claims", nil)
	r.SetPathValue("id", "u-1")
	w := httptest.NewRecorder()
	h.GetUserClaims(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d — body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var got domain.UserClaims
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Subject != "u-1" || got.Email != "alice@example.com" || !got.EmailVerified {
		t.Errorf("body = %+v, want sub=u-1, email=alice@example.com, verified=true", got)
	}
}

func TestGetUserClaims_MissingID_Returns400(t *testing.T) {
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())
	r := httptest.NewRequest(http.MethodGet, "/users//claims", nil)
	w := httptest.NewRecorder()
	h.GetUserClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetUserClaims_UserNotFound_Returns404(t *testing.T) {
	claims := &fakeClaims{err: apperrors.New(apperrors.ErrCodeNotFound, "no user")}
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, claims, testutil.NewTestLogger())
	r := httptest.NewRequest(http.MethodGet, "/users/u-bogus/claims", nil)
	r.SetPathValue("id", "u-bogus")
	w := httptest.NewRecorder()
	h.GetUserClaims(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestGetUserClaims_InternalError_Returns500AndLogs(t *testing.T) {
	spy := &spyLogger{Logger: testutil.NewTestLogger()}
	claims := &fakeClaims{err: apperrors.New(apperrors.ErrCodeInternal, "db down")}
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, claims, spy)
	r := httptest.NewRequest(http.MethodGet, "/users/u-1/claims", nil)
	r.SetPathValue("id", "u-1")
	w := httptest.NewRecorder()
	h.GetUserClaims(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if !spy.errorCalled {
		t.Error("logger.Error must be called for internal errors")
	}
}

// --- Health ---

func TestHealth_Returns200(t *testing.T) {
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, &fakeClaims{}, testutil.NewTestLogger())
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Health(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}
