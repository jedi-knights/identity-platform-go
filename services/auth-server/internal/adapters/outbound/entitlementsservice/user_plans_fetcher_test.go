package entitlementsservice_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/entitlementsservice"
)

const seatsFixture = `{
  "seats": [
    {
      "seat_id": "s-1",
      "account_id": "acc-other",
      "account_display_name": "Other",
      "role": "owner",
      "plan": {"id": "plan-other", "code": "touchline-free", "display_name": "Free"}
    },
    {
      "seat_id": "s-2",
      "account_id": "acc-active",
      "account_display_name": "Active",
      "role": "owner",
      "plan": {"id": "plan-active", "code": "touchline-coach", "display_name": "Coach"}
    }
  ]
}`

func TestUserPlansFetcher_ReturnsPlansForActiveAccount(t *testing.T) {
	var gotHeader, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Requester-User-ID")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(seatsFixture))
	}))
	defer srv.Close()

	f := entitlementsservice.NewUserPlansFetcher(srv.URL, srv.Client())
	got, err := f.GetUserPlans(context.Background(), "u-1", "acc-active")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "plan-active" {
		t.Errorf("plan_ids = %v, want [plan-active]", got)
	}
	if gotHeader != "u-1" {
		t.Errorf("X-Requester-User-ID = %q, want u-1", gotHeader)
	}
	if gotPath != "/users/u-1/seats" {
		t.Errorf("path = %q, want /users/u-1/seats", gotPath)
	}
}

// TestUserPlansFetcher_EmptyActiveAccountShortCircuits — a user who
// has never selected an account must not provoke a network call.
// Verified by using an invalid URL that would error on dial if the
// adapter ever reached the HTTP layer.
func TestUserPlansFetcher_EmptyActiveAccountShortCircuits(t *testing.T) {
	f := entitlementsservice.NewUserPlansFetcher("http://127.0.0.1:1", http.DefaultClient)
	got, err := f.GetUserPlans(context.Background(), "u-1", "")
	if err != nil {
		t.Fatalf("empty activeAccountID must not error: %v", err)
	}
	if got != nil {
		t.Errorf("plan_ids = %v, want nil (no account selected)", got)
	}
}

func TestUserPlansFetcher_NoMatchingSeatReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(seatsFixture))
	}))
	defer srv.Close()

	f := entitlementsservice.NewUserPlansFetcher(srv.URL, srv.Client())
	got, err := f.GetUserPlans(context.Background(), "u-1", "acc-unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("plan_ids = %v, want nil (no seat on acc-unknown)", got)
	}
}

func TestUserPlansFetcher_NullPlanReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"seats":[{"seat_id":"s","account_id":"acc-active","account_display_name":"X","role":"owner","plan":null}]}`))
	}))
	defer srv.Close()

	f := entitlementsservice.NewUserPlansFetcher(srv.URL, srv.Client())
	got, err := f.GetUserPlans(context.Background(), "u-1", "acc-active")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("plan_ids = %v, want nil (seat has null plan)", got)
	}
}

func TestUserPlansFetcher_ServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := entitlementsservice.NewUserPlansFetcher(srv.URL, srv.Client())
	if _, err := f.GetUserPlans(context.Background(), "u-1", "acc-active"); err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestUserPlansFetcher_MalformedJSONSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	f := entitlementsservice.NewUserPlansFetcher(srv.URL, srv.Client())
	if _, err := f.GetUserPlans(context.Background(), "u-1", "acc-active"); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestUserPlansFetcher_EmptyUserIDRejected(t *testing.T) {
	f := entitlementsservice.NewUserPlansFetcher("http://unused", http.DefaultClient)
	if _, err := f.GetUserPlans(context.Background(), "", "acc-active"); err == nil {
		t.Fatal("expected error on empty userID")
	}
}
