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
