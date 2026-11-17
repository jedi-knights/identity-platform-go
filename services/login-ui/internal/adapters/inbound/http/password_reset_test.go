package http_test

import (
	"context"
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
)

// fakePasswordResetter records calls and returns canned errors so every
// failure branch is reachable without a real identity-service.
type fakePasswordResetter struct {
	mu          sync.Mutex
	requested   []string
	resetTokens []string
	resetPws    []string
	requestErr  error
	resetErr    error
}

func (f *fakePasswordResetter) RequestReset(_ context.Context, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requested = append(f.requested, email)
	return f.requestErr
}

func (f *fakePasswordResetter) ResetPassword(_ context.Context, token, newPassword string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resetTokens = append(f.resetTokens, token)
	f.resetPws = append(f.resetPws, newPassword)
	return f.resetErr
}

func newResetRouter(pr *fakePasswordResetter) http.Handler {
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger)
	if pr != nil {
		h = h.WithPasswordReset(pr)
	}
	return authhttp.NewRouter(h, logger)
}

func serve(router http.Handler, method, target string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec
}

// mustContain fails the test for each want that is absent from body.
func mustContain(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body missing %q", w)
		}
	}
}

// mustNotContain fails the test for each bad that appears in body.
func mustNotContain(t *testing.T, body, why string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(body, b) {
			t.Errorf("body contains %q: %s", b, why)
		}
	}
}

func TestPasswordResetRoutes_Return503WhenUnwired(t *testing.T) {
	router := newResetRouter(nil)

	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/forgot-password"},
		{http.MethodPost, "/forgot-password"},
		{http.MethodGet, "/reset-password?token=t"},
		{http.MethodPost, "/reset-password"},
	} {
		if rec := serve(router, tc.method, tc.target, url.Values{}); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status = %d, want 503", tc.method, tc.target, rec.Code)
		}
	}
}

// --- /forgot-password ---

func TestForgotPasswordGet_RendersFormUncached(t *testing.T) {
	rec := serve(newResetRouter(&fakePasswordResetter{}), http.MethodGet, "/forgot-password", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `data-testid="forgot-form"`) {
		t.Error("body missing forgot-password form")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

func TestForgotPasswordPost_ForwardsEmailAndShowsNeutralConfirmation(t *testing.T) {
	pr := &fakePasswordResetter{}

	rec := serve(newResetRouter(pr), http.MethodPost, "/forgot-password", url.Values{"email": {"u@example.com"}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(pr.requested) != 1 || pr.requested[0] != "u@example.com" {
		t.Errorf("RequestReset calls = %v, want [u@example.com]", pr.requested)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-testid="sent"`) {
		t.Error("body missing confirmation")
	}
	if strings.Contains(strings.ToLower(body), "no account") || strings.Contains(strings.ToLower(body), "not found") {
		t.Error("confirmation must not reveal whether the account exists")
	}
}

func TestForgotPasswordPost_EmptyEmailIsInlineErrorWithoutUpstreamCall(t *testing.T) {
	pr := &fakePasswordResetter{}

	rec := serve(newResetRouter(pr), http.MethodPost, "/forgot-password", url.Values{"email": {"  "}})

	if !strings.Contains(rec.Body.String(), `data-testid="error"`) {
		t.Error("body missing inline error")
	}
	if len(pr.requested) != 0 {
		t.Errorf("upstream called %d times, want 0", len(pr.requested))
	}
}

func TestForgotPasswordPost_UpstreamFailuresAreUserSafe(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantText   string
	}{
		{"rate limited", apperrors.New(apperrors.ErrCodeRateLimit, "leaky internal detail"), http.StatusTooManyRequests, "Too many"},
		{"upstream down", apperrors.New(apperrors.ErrCodeInternal, "leaky internal detail"), http.StatusOK, "try again"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(newResetRouter(&fakePasswordResetter{requestErr: tc.err}), http.MethodPost, "/forgot-password", url.Values{"email": {"u@example.com"}})

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.wantText) {
				t.Errorf("body missing %q", tc.wantText)
			}
			if strings.Contains(body, "leaky internal detail") || strings.Contains(body, `data-testid="sent"`) {
				t.Error("failure must neither leak upstream detail nor claim the email was sent")
			}
		})
	}
}

func TestForgotPasswordGet_LinksBackToSignInOnlyWithinAnOAuthFlow(t *testing.T) {
	router := newResetRouter(&fakePasswordResetter{})

	withChallenge := serve(router, http.MethodGet, "/forgot-password?login_challenge=c1", nil)
	without := serve(router, http.MethodGet, "/forgot-password", nil)

	if !strings.Contains(withChallenge.Body.String(), `href="/sign-in?login_challenge=c1"`) {
		t.Error("should link back to the in-flight sign-in")
	}
	if strings.Contains(without.Body.String(), `href="/sign-in`) {
		t.Error("must not link to /sign-in without a challenge (it would 400)")
	}
}

// --- /reset-password ---

func TestResetPasswordGet_CarriesTokenInHiddenFieldAndLocksDownCaching(t *testing.T) {
	rec := serve(newResetRouter(&fakePasswordResetter{}), http.MethodGet, "/reset-password?token=abc123", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `name="token" value="abc123"`) {
		t.Error("token missing from hidden field")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer (token is in the URL)", rec.Header().Get("Referrer-Policy"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

func TestResetPasswordGet_EscapesTokenInMarkup(t *testing.T) {
	rec := serve(newResetRouter(&fakePasswordResetter{}), http.MethodGet, "/reset-password?"+url.Values{"token": {`"><script>alert(1)</script>`}}.Encode(), nil)

	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("token was reflected unescaped (XSS)")
	}
}

func TestResetPasswordGet_MissingTokenPointsToForgotPassword(t *testing.T) {
	rec := serve(newResetRouter(&fakePasswordResetter{}), http.MethodGet, "/reset-password", nil)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `href="/forgot-password"`) {
		t.Error("body should offer a way to request a new link")
	}
}

func TestResetPasswordPost_SuccessForwardsTokenAndPasswordAndTellsUserToReturnToApp(t *testing.T) {
	pr := &fakePasswordResetter{}

	rec := serve(newResetRouter(pr), http.MethodPost, "/reset-password", url.Values{
		"token": {"tok-1"}, "password": {"correct horse battery"}, "confirm_password": {"correct horse battery"},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(pr.resetTokens) != 1 || pr.resetTokens[0] != "tok-1" || pr.resetPws[0] != "correct horse battery" {
		t.Errorf("ResetPassword calls = %v / %v, want tok-1 / password", pr.resetTokens, pr.resetPws)
	}
	mustContain(t, rec.Body.String(), `data-testid="done"`)
	mustNotContain(t, rec.Body.String(), "/sign-in 400s without a login_challenge; the password must never be echoed",
		`href="/sign-in"`, "correct horse battery")
}

func TestResetPasswordPost_ValidationFailuresKeepTokenAndSkipUpstream(t *testing.T) {
	tests := []struct {
		name      string
		form      url.Values
		wantToken bool
	}{
		{"passwords differ", url.Values{"token": {"tok-1"}, "password": {"aaaaaaaa"}, "confirm_password": {"bbbbbbbb"}}, true},
		{"empty password", url.Values{"token": {"tok-1"}, "password": {""}, "confirm_password": {""}}, true},
		{"missing token", url.Values{"password": {"aaaaaaaa"}, "confirm_password": {"aaaaaaaa"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := &fakePasswordResetter{}

			rec := serve(newResetRouter(pr), http.MethodPost, "/reset-password", tc.form)

			body := rec.Body.String()
			mustContain(t, body, `data-testid="error"`)
			mustNotContain(t, body, "passwords must never be echoed", "aaaaaaaa", "bbbbbbbb")
			if tc.wantToken {
				mustContain(t, body, `name="token" value="tok-1"`) // survives so the user can retry
			}
			if len(pr.resetTokens) != 0 {
				t.Errorf("upstream called %d times, want 0", len(pr.resetTokens))
			}
		})
	}
}

func TestResetPasswordPost_UpstreamFailuresMapToUserSafeMessages(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantText   string
		wantLink   string
	}{
		{"bad or expired token", apperrors.New(apperrors.ErrCodeUnauthorized, "leaky"), http.StatusOK, "invalid or has expired", `href="/forgot-password"`},
		{"weak password", apperrors.New(apperrors.ErrCodeBadRequest, "leaky"), http.StatusOK, "requirements", `name="token" value="tok-1"`},
		{"rate limited", apperrors.New(apperrors.ErrCodeRateLimit, "leaky"), http.StatusTooManyRequests, "Too many", `name="token" value="tok-1"`},
		{"upstream down", apperrors.New(apperrors.ErrCodeInternal, "leaky"), http.StatusOK, "try again", `name="token" value="tok-1"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := &fakePasswordResetter{resetErr: tc.err}

			rec := serve(newResetRouter(pr), http.MethodPost, "/reset-password", url.Values{
				"token": {"tok-1"}, "password": {"correct horse battery"}, "confirm_password": {"correct horse battery"},
			})

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			mustContain(t, rec.Body.String(), tc.wantText, tc.wantLink)
			mustNotContain(t, rec.Body.String(), "no upstream detail, password, or success marker may appear",
				"leaky", "correct horse battery", `data-testid="done"`)
		})
	}
}

// --- sign-in discoverability ---

func TestSignInGet_LinksToForgotPasswordOnlyWhenWired(t *testing.T) {
	logger := logging.New(logging.Config{Output: io.Discard})
	signIn := func(pr *fakePasswordResetter) string {
		h := authhttp.NewHandler(&fakeUserAuth{}, &fakeCodeIssuer{}, logger)
		if pr != nil {
			h = h.WithPasswordReset(pr)
		}
		return serve(authhttp.NewRouter(h, logger), http.MethodGet, "/sign-in?login_challenge=c1", nil).Body.String()
	}

	wired, unwired := signIn(&fakePasswordResetter{}), signIn(nil)

	if !strings.Contains(wired, `data-testid="link-forgot"`) || !strings.Contains(wired, `href="/forgot-password?login_challenge=c1"`) {
		t.Error("wired sign-in page should link to /forgot-password and carry the challenge")
	}
	if strings.Contains(unwired, `data-testid="link-forgot"`) {
		t.Error("unwired sign-in page must not advertise a 503 page")
	}
}
