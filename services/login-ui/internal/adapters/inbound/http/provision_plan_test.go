package http_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

// fakePlanActivator records calls and can be programmed to fail up to
// failCount times before succeeding — the retry-loop assertions in
// TestCheckoutPost_ProvisionRetriesTransientFailures depend on it.
// Tier drives what the successful call reports back so E5-S3 tests can
// exercise both the free and paid branches; empty tier means the fake
// hands back the concrete "coach" default (matches the paid path).
type fakePlanActivator struct {
	calls     atomic.Int32
	failCount int32
	failWith  error
	lastReq   ports.ActivatePlanRequest
	tier      string
}

func (f *fakePlanActivator) ActivatePlan(_ context.Context, req ports.ActivatePlanRequest) (*ports.ActivatePlanResult, error) {
	f.lastReq = req
	if n := f.calls.Add(1); n <= f.failCount {
		return nil, f.failWith
	}
	tier := f.tier
	if tier == "" {
		tier = "coach"
	}
	return &ports.ActivatePlanResult{PlanTier: tier}, nil
}

// billingWithProvisioning is a fakeBilling that also records
// EnsureCustomer / CreateSubscription / CreateCheckoutSession so the
// composite tests can verify step order, inputs, and the composed
// cancel URL.
type billingWithProvisioning struct {
	ensureCalls atomic.Int32
	ensureReq   ports.EnsureCustomerRequest

	subCalls atomic.Int32
	subReq   ports.CreateSubscriptionRequest
	subResp  *ports.SubscriptionResult
	subErr   error

	checkoutReq  ports.CheckoutSessionRequest
	checkoutResp *ports.CheckoutSession
}

// lastCheckoutReq returns the most recent CheckoutSessionRequest the
// fake received. Tests use it to assert on the dynamic cancel URL
// CheckoutPost composes (E5-S3).
func (b *billingWithProvisioning) lastCheckoutReq() ports.CheckoutSessionRequest {
	return b.checkoutReq
}

func (b *billingWithProvisioning) ListPlans(_ context.Context) ([]ports.Plan, error) {
	return nil, nil
}

func (b *billingWithProvisioning) EnsureCustomer(_ context.Context, req ports.EnsureCustomerRequest) error {
	b.ensureReq = req
	b.ensureCalls.Add(1)
	return nil
}

func (b *billingWithProvisioning) CreateSubscription(_ context.Context, req ports.CreateSubscriptionRequest) (*ports.SubscriptionResult, error) {
	b.subReq = req
	b.subCalls.Add(1)
	if b.subErr != nil {
		return nil, b.subErr
	}
	return b.subResp, nil
}

func (b *billingWithProvisioning) CreateCheckoutSession(_ context.Context, req ports.CheckoutSessionRequest) (*ports.CheckoutSession, error) {
	b.checkoutReq = req
	return b.checkoutResp, nil
}

func (b *billingWithProvisioning) CreatePortalSession(_ context.Context, _ string) (*ports.PortalSession, error) {
	return nil, nil
}

func newProvisioningHandler(t *testing.T, b ports.BillingClient, pa ports.AccountPlanActivator) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(nil, nil, logger).
		WithBilling(b, "https://login-ui.test/billing/return", "https://login-ui.test/billing/plans").
		WithPlanActivator(pa)
	return h
}

func postCheckout(t *testing.T, h *authhttp.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CheckoutPost(w, req)
	return w
}

func TestCheckoutPost_ProvisionsThenRedirects(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-1"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/x"},
	}
	pa := &fakePlanActivator{}
	h := newProvisioningHandler(t, b, pa)

	form := url.Values{
		"subject":   {"u-1"},
		"account":   {"acc-1"},
		"plan_code": {"touchline-free"},
		"email":     {"u1@example.com"},
	}
	w := postCheckout(t, h, form)

	assertRedirect(t, w)
	assertEnsureCall(t, b)
	assertSubscriptionCall(t, b)
	assertActivateCall(t, pa)
}

func assertRedirect(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", w.Code, w.Body.String())
	}
}

func assertEnsureCall(t *testing.T, b *billingWithProvisioning) {
	t.Helper()
	if b.ensureCalls.Load() != 1 {
		t.Errorf("EnsureCustomer calls = %d, want 1", b.ensureCalls.Load())
	}
	if b.ensureReq.ExternalID != "acc-1" || b.ensureReq.Email != "u1@example.com" {
		t.Errorf("ensure req = %+v", b.ensureReq)
	}
}

func assertSubscriptionCall(t *testing.T, b *billingWithProvisioning) {
	t.Helper()
	if b.subReq.CustomerExternalID != "acc-1" || b.subReq.PlanCode != "touchline-free" {
		t.Errorf("sub req = %+v", b.subReq)
	}
	if b.subReq.ExternalID != "acc-1-touchline-free" {
		t.Errorf("sub external_id = %q, want deterministic acc-1-touchline-free", b.subReq.ExternalID)
	}
}

func assertActivateCall(t *testing.T, pa *fakePlanActivator) {
	t.Helper()
	if pa.calls.Load() != 1 {
		t.Errorf("ActivatePlan calls = %d", pa.calls.Load())
	}
	if pa.lastReq.LagoSubscriptionID != "sub-1" {
		t.Errorf("activate carried lago id = %q", pa.lastReq.LagoSubscriptionID)
	}
}

func TestCheckoutPost_ProvisionRetriesTransientFailures(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-1"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/x"},
	}
	pa := &fakePlanActivator{failCount: 2, failWith: errors.New("boom")}
	h := newProvisioningHandler(t, b, pa)

	form := url.Values{
		"subject": {"u-1"}, "account": {"acc-1"}, "plan_code": {"touchline-free"},
	}
	w := postCheckout(t, h, form)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 after 2 retries (body: %s)", w.Code, w.Body.String())
	}
	if pa.calls.Load() != 3 {
		t.Errorf("expected 3 ActivatePlan calls (2 failures + 1 success), got %d", pa.calls.Load())
	}
}

func TestCheckoutPost_ProvisionExhaustsRetriesReturns500(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-1"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/x"},
	}
	pa := &fakePlanActivator{failCount: 999, failWith: errors.New("permanent")}
	h := newProvisioningHandler(t, b, pa)

	form := url.Values{"subject": {"u-1"}, "account": {"acc-1"}, "plan_code": {"touchline-free"}}
	w := postCheckout(t, h, form)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 after retry exhaustion", w.Code)
	}
	if pa.calls.Load() != 3 {
		t.Errorf("expected 3 ActivatePlan calls at exhaustion, got %d", pa.calls.Load())
	}
}

func TestCheckoutPost_FallsBackToSubjectWhenAccountEmpty(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-1"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/x"},
	}
	pa := &fakePlanActivator{}
	h := newProvisioningHandler(t, b, pa)

	form := url.Values{"subject": {"u-1"}, "plan_code": {"touchline-free"}}
	w := postCheckout(t, h, form)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", w.Code, w.Body.String())
	}
	if b.ensureReq.ExternalID != "u-1" {
		t.Errorf("expected fallback external_id = u-1, got %q", b.ensureReq.ExternalID)
	}
}

// --- E5-S3: free/paid branch ---

func TestCheckoutPost_FreeTierSkipsStripe(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-free"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/should-not-hit"},
	}
	pa := &fakePlanActivator{tier: "free"}
	h := newProvisioningHandler(t, b, pa)

	form := url.Values{"subject": {"u-1"}, "account": {"acc-1"}, "plan_code": {"touchline-free"}}
	w := postCheckout(t, h, form)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	// Free-plan redirect goes to the configured success URL, never Stripe.
	if loc != "https://login-ui.test/billing/return" {
		t.Errorf("Location = %q, want billing/return", loc)
	}
	if strings.Contains(loc, "stripe") {
		t.Errorf("free tier must NOT redirect to Stripe; got %q", loc)
	}
}

func TestCheckoutPost_PaidTierContinuesToStripe(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-club"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/paid"},
	}
	pa := &fakePlanActivator{tier: "club"}
	h := newProvisioningHandler(t, b, pa)

	form := url.Values{"subject": {"u-1"}, "account": {"acc-1"}, "plan_code": {"touchline-club"}}
	w := postCheckout(t, h, form)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://checkout.stripe.test/paid" {
		t.Errorf("Location = %q, want Stripe URL", loc)
	}
}

func TestCheckoutPost_PaidTierCancelURLCarriesSubjectAndFlag(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-x"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/x"},
	}
	pa := &fakePlanActivator{tier: "club"}
	h := newProvisioningHandler(t, b, pa)

	form := url.Values{"subject": {"u-1"}, "account": {"acc-1"}, "plan_code": {"touchline-club"}}
	postCheckout(t, h, form)

	cancel := b.lastCheckoutReq().CancelURL
	if !strings.Contains(cancel, "checkout=canceled") {
		t.Errorf("cancel URL missing checkout=canceled flag: %q", cancel)
	}
	if !strings.Contains(cancel, "subject=u-1") || !strings.Contains(cancel, "account=acc-1") {
		t.Errorf("cancel URL missing subject/account: %q", cancel)
	}
}

// --- E8-S2a: OAuth loop closure on free-plan completion ---

// newOAuthProvisioningHandler wires a code issuer alongside the billing
// + plan activator. Mirrors newProvisioningHandler so the free-plan +
// login_challenge tests can assert on IssueCode interactions.
func newOAuthProvisioningHandler(t *testing.T, b ports.BillingClient, pa ports.AccountPlanActivator, ci ports.AuthCodeIssuer) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	return authhttp.NewHandler(nil, ci, logger).
		WithBilling(b, "https://login-ui.test/billing/return", "https://login-ui.test/billing/plans").
		WithPlanActivator(pa)
}

// TestCheckoutPost_FreeTier_WithLoginChallenge_ClosesOAuthLoop verifies
// the E8-S2a happy path: a free-plan completion inside an active OAuth
// flow consumes the challenge via /internal/issue-code and 302s to the
// RP's redirect_uri with ?code=&state=&iss=. Without this, Touchline's
// Auth.js has no code to exchange and no session gets established.
func TestCheckoutPost_FreeTier_WithLoginChallenge_ClosesOAuthLoop(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-free"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/should-not-hit"},
	}
	pa := &fakePlanActivator{tier: "free"}
	ci := &fakeCodeIssuer{resp: &ports.IssueCodeResponse{
		Code:        "code-abc",
		RedirectURI: "https://touchline.test/api/auth/callback/identity-platform",
		State:       "state-xyz",
		Issuer:      "https://identity.test",
	}}
	h := newOAuthProvisioningHandler(t, b, pa, ci)

	form := url.Values{
		"subject":         {"u-1"},
		"account":         {"acc-1"},
		"plan_code":       {"touchline-free"},
		"login_challenge": {"chall-42"},
	}
	w := postCheckout(t, h, form)

	assertOAuthLoopClosed(t, w, ci)
}

// assertOAuthLoopClosed centralizes the free-plan + login_challenge
// expectations. Extracted so TestCheckoutPost_FreeTier_WithLoginChallenge_
// ClosesOAuthLoop stays under the gocyclo budget while still asserting
// on every piece of the OAuth loop closure.
func assertOAuthLoopClosed(t *testing.T, w *httptest.ResponseRecorder, ci *fakeCodeIssuer) {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://touchline.test/api/auth/callback/identity-platform?") {
		t.Fatalf("Location = %q, want prefix touchline.test callback", loc)
	}
	checks := []struct {
		msg string
		ok  bool
	}{
		{"IssueCode.LoginChallenge != chall-42", ci.gotReq.LoginChallenge == "chall-42"},
		{"IssueCode.SessionID != u-1 (the fresh subject)", ci.gotReq.SessionID == "u-1"},
		{"Location missing code=code-abc", strings.Contains(loc, "code=code-abc")},
		{"Location missing state=state-xyz", strings.Contains(loc, "state=state-xyz")},
		{"Location missing iss claim", strings.Contains(loc, "iss=https%3A%2F%2Fidentity.test")},
		{"free tier must NOT go to Stripe", !strings.Contains(loc, "stripe")},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("%s (loc=%q, ci.gotReq=%+v)", c.msg, loc, ci.gotReq)
		}
	}
}

// TestCheckoutPost_FreeTier_WithoutLoginChallenge_FallsBackToReturnTo
// is the regression test for the pre-E8-S2a behavior: free-plan with
// no login_challenge keeps the operator-configured return_to path.
func TestCheckoutPost_FreeTier_WithoutLoginChallenge_FallsBackToReturnTo(t *testing.T) {
	b := &billingWithProvisioning{
		subResp:      &ports.SubscriptionResult{LagoID: "sub-free"},
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/should-not-hit"},
	}
	pa := &fakePlanActivator{tier: "free"}
	ci := &fakeCodeIssuer{}
	h := newOAuthProvisioningHandler(t, b, pa, ci)

	form := url.Values{
		"subject":   {"u-1"},
		"account":   {"acc-1"},
		"plan_code": {"touchline-free"},
	}
	w := postCheckout(t, h, form)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://login-ui.test/billing/return" {
		t.Errorf("Location = %q, want billing/return fallback", loc)
	}
	if ci.gotReq.LoginChallenge != "" {
		t.Errorf("IssueCode must not be called without login_challenge; got req = %+v", ci.gotReq)
	}
}
