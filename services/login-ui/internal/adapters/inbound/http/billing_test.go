package http_test

import (
	"context"
	"errors"
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

// fakeBilling records calls and serves pre-set responses.
type fakeBilling struct {
	listPlansResp []ports.Plan
	listPlansErr  error

	checkoutResp *ports.CheckoutSession
	checkoutErr  error
	checkoutReq  ports.CheckoutSessionRequest

	portalResp *ports.PortalSession
	portalErr  error
	portalArg  string
}

func (f *fakeBilling) ListPlans(_ context.Context) ([]ports.Plan, error) {
	return f.listPlansResp, f.listPlansErr
}

func (f *fakeBilling) CreateCheckoutSession(_ context.Context, req ports.CheckoutSessionRequest) (*ports.CheckoutSession, error) {
	f.checkoutReq = req
	if f.checkoutErr != nil {
		return nil, f.checkoutErr
	}
	return f.checkoutResp, nil
}

func (f *fakeBilling) CreatePortalSession(_ context.Context, customerID string) (*ports.PortalSession, error) {
	f.portalArg = customerID
	if f.portalErr != nil {
		return nil, f.portalErr
	}
	return f.portalResp, nil
}

func newBillingHandler(t *testing.T, b ports.BillingClient) *authhttp.Handler {
	t.Helper()
	logger := logging.New(logging.Config{Output: io.Discard})
	h := authhttp.NewHandler(&fakeUserAuth{}, &fakeCodeIssuer{}, logger)
	if b != nil {
		h = h.WithBilling(b, "https://login-ui.test/billing/return", "https://login-ui.test/billing/plans?subject=u-1")
	}
	return h
}

func TestPlansGet_NoBillingConfigured_Returns503(t *testing.T) {
	h := newBillingHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/billing/plans?subject=u-1", nil)
	w := httptest.NewRecorder()
	h.PlansGet(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestPlansGet_RendersActivePlans(t *testing.T) {
	billing := &fakeBilling{
		listPlansResp: []ports.Plan{
			{Code: "starter", Name: "Starter", AmountCents: 0, Currency: "USD", Interval: "monthly"},
			{Code: "pro", Name: "Pro", Description: "everything in starter plus...", AmountCents: 1900, Currency: "USD", Interval: "monthly"},
		},
	}
	h := newBillingHandler(t, billing)
	req := httptest.NewRequest(http.MethodGet, "/billing/plans?subject=u-1", nil)
	w := httptest.NewRecorder()
	h.PlansGet(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Starter") {
		t.Errorf("body missing Starter plan")
	}
	if !strings.Contains(body, "$19.00") {
		t.Errorf("body missing $19.00 price for Pro")
	}
	if !strings.Contains(body, `value="u-1"`) {
		t.Errorf("subject hidden field not rendered")
	}
}

func TestPlansGet_LagoError_RendersErrorBanner(t *testing.T) {
	billing := &fakeBilling{listPlansErr: errors.New("lago down")}
	h := newBillingHandler(t, billing)
	req := httptest.NewRequest(http.MethodGet, "/billing/plans?subject=u-1", nil)
	w := httptest.NewRecorder()
	h.PlansGet(w, req)
	if w.Code != http.StatusOK {
		// The handler always returns 200 with an inline error so the page
		// stays renderable when Lago has a hiccup — the user can refresh.
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Could not load plans") {
		t.Errorf("expected error banner; got %q", w.Body.String())
	}
}

func TestCheckoutPost_HappyPath_RedirectsToStripe(t *testing.T) {
	billing := &fakeBilling{
		checkoutResp: &ports.CheckoutSession{URL: "https://checkout.stripe.test/abc"},
	}
	h := newBillingHandler(t, billing)
	form := url.Values{"subject": {"u-1"}, "plan_code": {"pro"}}
	req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CheckoutPost(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://checkout.stripe.test/abc" {
		t.Errorf("Location = %q", loc)
	}
	if billing.checkoutReq.CustomerID != "u-1" {
		t.Errorf("CustomerID = %q, want u-1", billing.checkoutReq.CustomerID)
	}
	if billing.checkoutReq.PlanCode != "pro" {
		t.Errorf("PlanCode = %q, want pro", billing.checkoutReq.PlanCode)
	}
	if billing.checkoutReq.SuccessURL != "https://login-ui.test/billing/return" {
		t.Errorf("SuccessURL = %q", billing.checkoutReq.SuccessURL)
	}
}

func TestCheckoutPost_MissingFields_Returns400(t *testing.T) {
	billing := &fakeBilling{}
	h := newBillingHandler(t, billing)
	tests := []url.Values{
		{"plan_code": {"pro"}},
		{"subject": {"u-1"}},
		{},
	}
	for _, form := range tests {
		req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.CheckoutPost(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("form %v: status = %d, want 400", form, w.Code)
		}
	}
}

func TestCheckoutPost_LagoFailure_Returns500(t *testing.T) {
	billing := &fakeBilling{checkoutErr: errors.New("lago boom")}
	h := newBillingHandler(t, billing)
	form := url.Values{"subject": {"u-1"}, "plan_code": {"pro"}}
	req := httptest.NewRequest(http.MethodPost, "/billing/checkout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CheckoutPost(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPortalGet_HappyPath_Redirects(t *testing.T) {
	billing := &fakeBilling{portalResp: &ports.PortalSession{URL: "https://portal.stripe.test/x"}}
	h := newBillingHandler(t, billing)
	req := httptest.NewRequest(http.MethodGet, "/billing/portal?subject=u-1", nil)
	w := httptest.NewRecorder()
	h.PortalGet(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://portal.stripe.test/x" {
		t.Errorf("Location = %q", loc)
	}
	if billing.portalArg != "u-1" {
		t.Errorf("portal customer id = %q", billing.portalArg)
	}
}

func TestPortalGet_MissingSubject_Returns400(t *testing.T) {
	billing := &fakeBilling{}
	h := newBillingHandler(t, billing)
	req := httptest.NewRequest(http.MethodGet, "/billing/portal", nil)
	w := httptest.NewRecorder()
	h.PortalGet(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestBillingRoutes_503WhenBillingNotConfigured(t *testing.T) {
	h := newBillingHandler(t, nil)
	tests := []struct {
		name    string
		req     *http.Request
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{"plans", httptest.NewRequest(http.MethodGet, "/billing/plans", nil), h.PlansGet},
		{"checkout", httptest.NewRequest(http.MethodPost, "/billing/checkout", nil), h.CheckoutPost},
		{"portal", httptest.NewRequest(http.MethodGet, "/billing/portal", nil), h.PortalGet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.handler(w, tt.req)
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", w.Code)
			}
		})
	}
}
