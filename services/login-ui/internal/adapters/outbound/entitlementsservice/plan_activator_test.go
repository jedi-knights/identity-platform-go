package entitlementsservice_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/entitlementsservice"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

func TestPlanActivator_PostsExpectedShape(t *testing.T) {
	var gotBody []byte
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"account_plan_id":"ap-1","account_id":"acc-1","plan_id":"p-1","created":true}`))
	}))
	defer srv.Close()

	a := entitlementsservice.NewPlanActivator(srv.URL, srv.Client())
	res, err := a.ActivatePlan(context.Background(), ports.ActivatePlanRequest{
		AccountID:          "acc-1",
		PlanCode:           "touchline-free",
		LagoSubscriptionID: "sub-abc",
	})
	if err != nil {
		t.Fatalf("ActivatePlan: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if gotPath != "/accounts/acc-1/plans" {
		t.Errorf("path = %q", gotPath)
	}
	var wire struct {
		PlanCode           string `json:"plan_code"`
		LagoSubscriptionID string `json:"lago_subscription_id"`
	}
	if err := json.Unmarshal(gotBody, &wire); err != nil {
		t.Fatalf("body: %v — %s", err, gotBody)
	}
	if wire.PlanCode != "touchline-free" {
		t.Errorf("plan_code = %q", wire.PlanCode)
	}
	if wire.LagoSubscriptionID != "sub-abc" {
		t.Errorf("lago_subscription_id = %q", wire.LagoSubscriptionID)
	}
}

func TestPlanActivator_TreatsIdempotent200AsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"created":false,"plan_tier":"free"}`))
	}))
	defer srv.Close()

	a := entitlementsservice.NewPlanActivator(srv.URL, srv.Client())
	res, err := a.ActivatePlan(context.Background(), ports.ActivatePlanRequest{
		AccountID: "acc-1", PlanCode: "touchline-free",
	})
	if err != nil {
		t.Fatalf("idempotent replay should be a success: %v", err)
	}
	if res.PlanTier != "free" {
		t.Errorf("PlanTier = %q, want free", res.PlanTier)
	}
}

func TestPlanActivator_ReturnsTierFromResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"account_plan_id":"ap-1","plan_tier":"club","created":true}`))
	}))
	defer srv.Close()

	a := entitlementsservice.NewPlanActivator(srv.URL, srv.Client())
	res, err := a.ActivatePlan(context.Background(), ports.ActivatePlanRequest{
		AccountID: "acc-1", PlanCode: "touchline-club",
	})
	if err != nil {
		t.Fatalf("ActivatePlan: %v", err)
	}
	if res.PlanTier != "club" {
		t.Errorf("PlanTier = %q, want club", res.PlanTier)
	}
}

func TestPlanActivator_Non2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	a := entitlementsservice.NewPlanActivator(srv.URL, srv.Client())
	_, err := a.ActivatePlan(context.Background(), ports.ActivatePlanRequest{
		AccountID: "acc-1", PlanCode: "touchline-free",
	})
	if err == nil {
		t.Fatal("expected error on 409")
	}
}

func TestPlanActivator_ValidationFailsFast(t *testing.T) {
	a := entitlementsservice.NewPlanActivator("http://localhost", http.DefaultClient)
	cases := []ports.ActivatePlanRequest{
		{PlanCode: "touchline-free"},
		{AccountID: "acc-1"},
	}
	for _, tc := range cases {
		if _, err := a.ActivatePlan(context.Background(), tc); err == nil {
			t.Errorf("expected error for %+v", tc)
		}
	}
}
