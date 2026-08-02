package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// newE5S4Handler is a mirror of newProvisioningHandler with an
// allowlist wired so the E5-S4 return-URL branches are exercised.
func newE5S4Handler(t *testing.T, b ports.BillingClient, pa ports.AccountPlanActivator, allowed string) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(nil, nil, logger).
		WithBilling(b, "https://login-ui.example.com/billing/return", "https://login-ui.example.com/billing/plans").
		WithPlanActivator(pa).
		WithAllowedReturnHosts(allowed)
}

func TestCheckoutPost_FreeTier_HonoursAllowlistedReturnTo(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-free"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/should-not-hit"},
	}
	pa := &fakePlanActivator{tier: "free"}
	h := newE5S4Handler(t, b, pa, "touchline.example.com")

	form := url.Values{
		"subject":   {"u-1"},
		"account":   {"acc-1"},
		"plan_code": {"touchline-free"},
		"return_to": {"https://touchline.example.com/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CheckoutPost(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://touchline.example.com/dashboard" {
		t.Errorf("Location = %q, want originating app URL", loc)
	}
}

func TestCheckoutPost_FreeTier_RejectsUnlistedReturnTo(t *testing.T) {
	b := &billingWithProvisioning{
		subResp: &ports.SubscriptionResult{LagoID: "sub-free"},
	}
	pa := &fakePlanActivator{tier: "free"}
	h := newE5S4Handler(t, b, pa, "touchline.example.com")

	form := url.Values{
		"subject":   {"u-1"},
		"account":   {"acc-1"},
		"plan_code": {"touchline-free"},
		"return_to": {"https://evil.example/steal"},
	}
	req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CheckoutPost(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	// Rejected return_to falls back to the configured success URL —
	// evil.example must NEVER appear in the Location header.
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "evil.example") {
		t.Errorf("open-redirect: Location = %q leaks unlisted host", loc)
	}
	if loc != "https://login-ui.example.com/billing/return" {
		t.Errorf("Location = %q, want fallback billingSuccessURL", loc)
	}
}

func TestCheckoutPost_PaidTier_EmbedsReturnToInStripeSuccessURL(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-club"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/paid"},
	}
	pa := &fakePlanActivator{tier: "club"}
	h := newE5S4Handler(t, b, pa, "touchline.example.com")

	form := url.Values{
		"subject":   {"u-1"},
		"account":   {"acc-1"},
		"plan_code": {"touchline-club"},
		"return_to": {"https://touchline.example.com/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CheckoutPost(w, req)

	success := b.lastCheckoutReq().SuccessURL
	if !strings.Contains(success, "return_to=") {
		t.Errorf("Stripe successURL missing return_to: %q", success)
	}
	if !strings.Contains(success, "touchline.example.com%2Fdashboard") &&
		!strings.Contains(success, "touchline.example.com/dashboard") {
		t.Errorf("Stripe successURL missing originating-app URL: %q", success)
	}
	if _ = w; w.Code != http.StatusFound {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestCheckoutPost_PaidTier_UnlistedReturnToDropsIt(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-club"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/paid"},
	}
	pa := &fakePlanActivator{tier: "club"}
	h := newE5S4Handler(t, b, pa, "touchline.example.com")

	form := url.Values{
		"subject":   {"u-1"},
		"account":   {"acc-1"},
		"plan_code": {"touchline-club"},
		"return_to": {"https://evil.example/steal"},
	}
	req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CheckoutPost(w, req)

	success := b.lastCheckoutReq().SuccessURL
	if strings.Contains(success, "evil.example") {
		t.Errorf("open-redirect: successURL = %q leaks unlisted host", success)
	}
	if _ = w; w.Code != http.StatusFound {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestReturnGet_ValidRedirectsToOriginatingApp(t *testing.T) {
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger).
		WithAllowedReturnHosts("touchline.example.com")

	req := httptest.NewRequest(http.MethodGet,
		"/billing/return?return_to=https%3A%2F%2Ftouchline.example.com%2Fdashboard", nil)
	w := httptest.NewRecorder()
	h.ReturnGet(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://touchline.example.com/dashboard" {
		t.Errorf("Location = %q", loc)
	}
}

func TestReturnGet_InvalidRendersLandingPage(t *testing.T) {
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger).
		WithAllowedReturnHosts("touchline.example.com")

	req := httptest.NewRequest(http.MethodGet,
		"/billing/return?return_to=https%3A%2F%2Fevil.example%2Fsteal", nil)
	w := httptest.NewRecorder()
	h.ReturnGet(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (landing page)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "All set") {
		t.Errorf("body missing landing text: %s", w.Body.String())
	}
	if loc := w.Header().Get("Location"); strings.Contains(loc, "evil.example") {
		t.Errorf("open-redirect: Location leaks unlisted host: %q", loc)
	}
}

func TestReturnGet_MissingReturnToRendersLandingPage(t *testing.T) {
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger).
		WithAllowedReturnHosts("touchline.example.com")

	req := httptest.NewRequest(http.MethodGet, "/billing/return", nil)
	w := httptest.NewRecorder()
	h.ReturnGet(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "All set") {
		t.Errorf("body missing landing text: %s", w.Body.String())
	}
}

func TestSignUpPost_PreservesRedirectURI(t *testing.T) {
	reg := &fakeRegistrar{resp: &ports.RegisterResult{UserID: "u-42", AccountID: "acc-42"}}
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger).WithRegistrar(reg)

	form := url.Values{
		"name":         {"Alice"},
		"email":        {"a@example.com"},
		"password":     {"hunter2"},
		"redirect_uri": {"https://touchline.example.com/dashboard"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.SignUpPost(w, req)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "return_to=") {
		t.Errorf("plans redirect missing return_to: %q", loc)
	}
	if !strings.Contains(loc, "touchline.example.com") {
		t.Errorf("plans redirect missing originating URL: %q", loc)
	}
}
