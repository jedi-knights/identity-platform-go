package entitlementsservice_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/entitlementsservice"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

func TestSeatLister_ReturnsSeats(t *testing.T) {
	var gotHeader, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Requester-User-ID")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"seats":[
			{"seat_id":"s1","account_id":"a1","account_display_name":"Personal","role":"owner","plan":null},
			{"seat_id":"s2","account_id":"a2","account_display_name":"Club","role":"member","plan":{"id":"p1","code":"touchline-club","display_name":"Touchline Club"}}
		]}`))
	}))
	defer srv.Close()

	l := entitlementsservice.NewSeatLister(srv.URL, srv.Client())
	got, err := l.ListUserSeats(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSeatsRequestAndBody(t, gotPath, gotHeader, got)
}

// assertSeatsRequestAndBody delegates the request-shape check and the
// body-shape check to focused helpers, each of which stays under the
// gocyclo budget.
func assertSeatsRequestAndBody(t *testing.T, gotPath, gotHeader string, got []ports.AccountSeat) {
	t.Helper()
	assertSeatsRequestShape(t, gotPath, gotHeader)
	assertSeatsBody(t, got)
}

func assertSeatsRequestShape(t *testing.T, gotPath, gotHeader string) {
	t.Helper()
	if gotPath != "/users/u-1/seats" {
		t.Errorf("path = %q, want /users/u-1/seats", gotPath)
	}
	if gotHeader != "u-1" {
		t.Errorf("X-Requester-User-ID = %q, want u-1", gotHeader)
	}
}

func assertSeatsBody(t *testing.T, got []ports.AccountSeat) {
	t.Helper()
	if len(got) != 2 {
		t.Fatalf("want 2 seats, got %d", len(got))
	}
	if got[0].AccountDisplayName != "Personal" || got[0].PlanCode != "" {
		t.Errorf("seat[0] = %+v", got[0])
	}
	if got[1].PlanCode != "touchline-club" || got[1].PlanName != "Touchline Club" {
		t.Errorf("seat[1] plan = %+v", got[1])
	}
}

func TestSeatLister_EmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"seats":[]}`))
	}))
	defer srv.Close()

	l := entitlementsservice.NewSeatLister(srv.URL, srv.Client())
	got, err := l.ListUserSeats(context.Background(), "u-empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 seats, got %d", len(got))
	}
}

func TestSeatLister_ServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	l := entitlementsservice.NewSeatLister(srv.URL, srv.Client())
	_, err := l.ListUserSeats(context.Background(), "u-1")
	if err == nil {
		t.Fatal("want error on 500, got nil")
	}
}

func TestSeatLister_RejectsEmptyUserID(t *testing.T) {
	l := entitlementsservice.NewSeatLister("http://ignored", http.DefaultClient)
	_, err := l.ListUserSeats(context.Background(), "")
	if err == nil {
		t.Fatal("want error on empty user_id, got nil")
	}
}
