package lago_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	lagoadapter "github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/lago"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

func TestEnsureCustomer_PostsExternalID(t *testing.T) {
	var gotBody []byte
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"customer":{"external_id":"acc-1"}}`))
	}))
	defer srv.Close()

	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	err := client.EnsureCustomer(context.Background(), ports.EnsureCustomerRequest{
		ExternalID: "acc-1",
		Email:      "u1@example.com",
	})
	if err != nil {
		t.Fatalf("EnsureCustomer: %v", err)
	}
	if gotPath != "/api/v1/customers" {
		t.Errorf("path = %q", gotPath)
	}
	var wire struct {
		Customer struct {
			ExternalID string `json:"external_id"`
			Email      string `json:"email"`
		} `json:"customer"`
	}
	if err := json.Unmarshal(gotBody, &wire); err != nil {
		t.Fatalf("body not JSON: %v — %s", err, gotBody)
	}
	if wire.Customer.ExternalID != "acc-1" {
		t.Errorf("external_id = %q", wire.Customer.ExternalID)
	}
	if wire.Customer.Email != "u1@example.com" {
		t.Errorf("email = %q", wire.Customer.Email)
	}
}

func TestEnsureCustomer_OmitsEmailWhenEmpty(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"customer":{"external_id":"acc-1"}}`))
	}))
	defer srv.Close()

	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	if err := client.EnsureCustomer(context.Background(), ports.EnsureCustomerRequest{
		ExternalID: "acc-1",
	}); err != nil {
		t.Fatalf("EnsureCustomer: %v", err)
	}
	if strings.Contains(string(gotBody), "email") {
		t.Errorf("body should not contain email key: %s", gotBody)
	}
}

func TestEnsureCustomer_EmptyExternalIDErrors(t *testing.T) {
	client := lagoadapter.New("https://lago.test", "test-key", nil)
	if err := client.EnsureCustomer(context.Background(), ports.EnsureCustomerRequest{}); err == nil {
		t.Fatal("expected error for empty external_id")
	}
}

func TestCreateSubscription_ReturnsLagoID(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		if r.URL.Path != "/api/v1/subscriptions" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"subscription":{"lago_id":"sub-abc","external_id":"acc-1-touchline-free"}}`))
	}))
	defer srv.Close()

	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	got, err := client.CreateSubscription(context.Background(), ports.CreateSubscriptionRequest{
		CustomerExternalID: "acc-1",
		PlanCode:           "touchline-free",
		ExternalID:         "acc-1-touchline-free",
	})
	if err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if got.LagoID != "sub-abc" {
		t.Errorf("lago_id = %q", got.LagoID)
	}
	var wire struct {
		Subscription struct {
			ExternalCustomerID string `json:"external_customer_id"`
			PlanCode           string `json:"plan_code"`
			ExternalID         string `json:"external_id"`
		} `json:"subscription"`
	}
	if err := json.Unmarshal(gotBody, &wire); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if wire.Subscription.ExternalID != "acc-1-touchline-free" {
		t.Errorf("external_id in body = %q", wire.Subscription.ExternalID)
	}
}

func TestCreateSubscription_DuplicateExternalIDFallsBackToGet(t *testing.T) {
	var seenPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"status":422,"error":"Unprocessable Entity","error_details":{"external_id":["value_already_exist"]}}`))
			return
		}
		// GET lookup path — return the existing sub.
		_, _ = w.Write([]byte(`{"subscription":{"lago_id":"sub-existing"}}`))
	}))
	defer srv.Close()

	client := lagoadapter.New(srv.URL, "test-key", srv.Client())
	got, err := client.CreateSubscription(context.Background(), ports.CreateSubscriptionRequest{
		CustomerExternalID: "acc-1",
		PlanCode:           "touchline-free",
		ExternalID:         "acc-1-touchline-free",
	})
	if err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if got.LagoID != "sub-existing" {
		t.Errorf("expected lago_id from GET lookup, got %q", got.LagoID)
	}
	if len(seenPaths) != 2 {
		t.Fatalf("expected POST then GET, got %v", seenPaths)
	}
	if seenPaths[1] != "GET /api/v1/subscriptions/acc-1-touchline-free" {
		t.Errorf("GET path = %q", seenPaths[1])
	}
}

func TestCreateSubscription_MissingFieldsError(t *testing.T) {
	client := lagoadapter.New("https://lago.test", "test-key", nil)
	cases := []ports.CreateSubscriptionRequest{
		{PlanCode: "pro", ExternalID: "k"},
		{CustomerExternalID: "c", ExternalID: "k"},
		{CustomerExternalID: "c", PlanCode: "pro"},
	}
	for _, tc := range cases {
		if _, err := client.CreateSubscription(context.Background(), tc); err == nil {
			t.Errorf("expected error for %+v", tc)
		}
	}
}
