package lago_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	lagoadapter "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/lago"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

func TestListPlans_FiltersInactiveAndMapsShape(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/plans" {
			t.Errorf("path = %q, want /api/v1/plans", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"plans":[
			{"code":"free","name":"Free","amount_cents":0,"amount_currency":"USD","interval":"monthly","active":true},
			{"code":"legacy","name":"Legacy","amount_cents":900,"amount_currency":"USD","interval":"monthly","active":false},
			{"code":"pro","name":"Pro","description":"all the things","amount_cents":1900,"amount_currency":"USD","interval":"monthly","active":true}
		]}`))
	}))
	defer srv.Close()

	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	plans, err := client.ListPlans(context.Background())
	if err != nil {
		t.Fatalf("ListPlans: %v", err)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if len(plans) != 2 {
		t.Fatalf("expected 2 active plans, got %d", len(plans))
	}
	codes := []string{plans[0].Code, plans[1].Code}
	if codes[0] != "free" || codes[1] != "pro" {
		t.Errorf("plans = %v, want [free pro]", codes)
	}
}

func TestCreateCheckoutSession_PostsCorrectBody(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertCheckoutRequest(t, r)
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"checkout_session":{"url":"https://checkout.stripe.test/abc"}}`))
	}))
	defer srv.Close()

	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	session, err := client.CreateCheckoutSession(context.Background(), ports.CheckoutSessionRequest{
		CustomerID: "u-1",
		PlanCode:   "pro",
		SuccessURL: "https://login-ui.test/ok",
		CancelURL:  "https://login-ui.test/cancel",
	})
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if session.URL != "https://checkout.stripe.test/abc" {
		t.Errorf("session url = %q", session.URL)
	}
	assertCheckoutBody(t, gotBody)
}

// assertCheckoutRequest verifies the inbound request shape. Extracted
// so the calling test stays under the gocyclo budget.
func assertCheckoutRequest(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", r.Method)
	}
	if r.URL.Path != "/api/v1/checkout_sessions" {
		t.Errorf("path = %q", r.URL.Path)
	}
}

// assertCheckoutBody decodes the wire body and verifies every field.
// Extracted so the calling test stays under the gocyclo budget.
func assertCheckoutBody(t *testing.T, gotBody []byte) {
	t.Helper()
	var wire struct {
		CheckoutSession struct {
			ExternalCustomerID string `json:"external_customer_id"`
			PlanCode           string `json:"plan_code"`
			SuccessURL         string `json:"success_url"`
			CancelURL          string `json:"cancel_url"`
		} `json:"checkout_session"`
	}
	if err := json.Unmarshal(gotBody, &wire); err != nil {
		t.Fatalf("body not JSON: %v\n%s", err, gotBody)
	}
	if wire.CheckoutSession.ExternalCustomerID != "u-1" {
		t.Errorf("external_customer_id = %q", wire.CheckoutSession.ExternalCustomerID)
	}
	if wire.CheckoutSession.PlanCode != "pro" {
		t.Errorf("plan_code = %q", wire.CheckoutSession.PlanCode)
	}
}

func TestCreatePortalSession_PostsAndReturnsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"customer_portal":{"url":"https://portal.stripe.test/x"}}`))
	}))
	defer srv.Close()
	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	got, err := client.CreatePortalSession(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("CreatePortalSession: %v", err)
	}
	if got.URL != "https://portal.stripe.test/x" {
		t.Errorf("url = %q", got.URL)
	}
}

func TestNon2xx_ReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"plan not found"}`))
	}))
	defer srv.Close()
	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	_, err := client.ListPlans(context.Background())
	if err == nil {
		t.Fatal("expected error on 422")
	}
	var apiErr *lagoadapter.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d", apiErr.Status)
	}
	if !strings.Contains(apiErr.Body, "plan not found") {
		t.Errorf("body = %q", apiErr.Body)
	}
}

func TestNew_EmptyBaseURLPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = lagoadapter.New("", "test-key", nil)
}

func TestNew_EmptyAPIKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = lagoadapter.New("https://lago.test", "", nil)
}
