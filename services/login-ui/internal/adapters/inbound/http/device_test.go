package http_test

import (
	"context"
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

type fakeDeviceDecider struct {
	mu     sync.Mutex
	gotReq ports.DeviceDecisionRequest
	err    error
}

func (f *fakeDeviceDecider) Decide(_ context.Context, req ports.DeviceDecisionRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotReq = req
	return f.err
}

func newDeviceHandler(t *testing.T, ua *fakeUserAuth, dd *fakeDeviceDecider) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(ua, &fakeCodeIssuer{}, logger).WithDeviceDecider(dd)
}

func TestDeviceGet_RendersFormWithUserCodePrefilled(t *testing.T) {
	// Arrange
	h := newDeviceHandler(t, &fakeUserAuth{}, &fakeDeviceDecider{})
	r := httptest.NewRequest(http.MethodGet, "/device?user_code=ABCD-1234", nil)
	w := httptest.NewRecorder()

	// Act
	h.DeviceGet(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ABCD-1234") {
		t.Errorf("body does not contain prefilled user_code: %s", w.Body.String())
	}
}

func TestDeviceGet_Degraded_Returns503(t *testing.T) {
	// Arrange — deviceDecider not wired.
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(&fakeUserAuth{}, &fakeCodeIssuer{}, logger)
	r := httptest.NewRequest(http.MethodGet, "/device", nil)
	w := httptest.NewRecorder()

	// Act
	h.DeviceGet(w, r)

	// Assert
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestDevicePost_ApproveHappyPath(t *testing.T) {
	// Arrange
	ua := &fakeUserAuth{subject: "user-42"}
	dd := &fakeDeviceDecider{}
	h := newDeviceHandler(t, ua, dd)
	form := url.Values{
		"user_code": {"ABCD-1234"},
		"email":     {"alice@example.com"},
		"password":  {"correct-password"},
		"decision":  {"approve"},
	}
	r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.DevicePost(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if dd.gotReq.UserCode != "ABCD-1234" || dd.gotReq.Subject != "user-42" || !dd.gotReq.Approved {
		t.Errorf("deviceDecider.Decide called with %+v", dd.gotReq)
	}
	if !strings.Contains(w.Body.String(), "approved") {
		t.Errorf("body does not confirm approval: %s", w.Body.String())
	}
}

func TestDevicePost_DenyHappyPath_NoCredentialsRequired(t *testing.T) {
	// Arrange — denying does not require the user to authenticate.
	ua := &fakeUserAuth{}
	dd := &fakeDeviceDecider{}
	h := newDeviceHandler(t, ua, dd)
	form := url.Values{"user_code": {"ABCD-1234"}, "decision": {"deny"}}
	r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.DevicePost(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if dd.gotReq.UserCode != "ABCD-1234" || dd.gotReq.Approved {
		t.Errorf("deviceDecider.Decide called with %+v, want Approved=false", dd.gotReq)
	}
	ua.mu.Lock()
	calledAuth := ua.gotEmail != ""
	ua.mu.Unlock()
	if calledAuth {
		t.Error("VerifyCredentials must not be called on deny")
	}
}

func TestDevicePost_BadCredentials_RendersFormWithError(t *testing.T) {
	// Arrange
	ua := &fakeUserAuth{err: apperrors.New(apperrors.ErrCodeUnauthorized, "bad password")}
	dd := &fakeDeviceDecider{}
	h := newDeviceHandler(t, ua, dd)
	form := url.Values{
		"user_code": {"ABCD-1234"},
		"email":     {"alice@example.com"},
		"password":  {"wrong"},
		"decision":  {"approve"},
	}
	r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.DevicePost(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid email or password") {
		t.Errorf("body does not show credential error: %s", w.Body.String())
	}
}

func TestDevicePost_MissingUserCode_RendersFormWithError(t *testing.T) {
	// Arrange
	h := newDeviceHandler(t, &fakeUserAuth{}, &fakeDeviceDecider{})
	form := url.Values{"decision": {"approve"}}
	r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.DevicePost(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "required") {
		t.Errorf("body does not show validation error: %s", w.Body.String())
	}
}

func TestDevicePost_ApproveMissingCredentials_RendersFormWithError(t *testing.T) {
	// Arrange
	h := newDeviceHandler(t, &fakeUserAuth{}, &fakeDeviceDecider{})
	form := url.Values{"user_code": {"ABCD-1234"}, "decision": {"approve"}}
	r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.DevicePost(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "required") {
		t.Errorf("body does not show validation error: %s", w.Body.String())
	}
}

func TestDevicePost_DeciderFails_RendersGenericError(t *testing.T) {
	// Arrange
	ua := &fakeUserAuth{subject: "user-42"}
	dd := &fakeDeviceDecider{err: errors.New("auth-server unavailable")}
	h := newDeviceHandler(t, ua, dd)
	form := url.Values{
		"user_code": {"ABCD-1234"},
		"email":     {"alice@example.com"},
		"password":  {"correct-password"},
		"decision":  {"approve"},
	}
	r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.DevicePost(w, r)

	// Assert
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "could not complete") {
		t.Errorf("body does not show generic error: %s", w.Body.String())
	}
}

func TestDevicePost_Degraded_Returns503(t *testing.T) {
	// Arrange — deviceDecider not wired.
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(&fakeUserAuth{}, &fakeCodeIssuer{}, logger)
	r := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	h.DevicePost(w, r)

	// Assert
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}
