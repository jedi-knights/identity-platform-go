package identityservice_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/identityservice"
)

func TestActiveAccountFetcher_ReturnsAccountID(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Requester-User-ID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":"acc-abc"}`))
	}))
	defer srv.Close()

	f := identityservice.NewActiveAccountFetcher(srv.URL, srv.Client())
	got, err := f.GetActiveAccount(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "acc-abc" {
		t.Errorf("account_id = %q, want acc-abc", got)
	}
	if gotHeader != "u-1" {
		t.Errorf("X-Requester-User-ID = %q, want u-1", gotHeader)
	}
}

func TestActiveAccountFetcher_ReturnsEmptyOnNull(t *testing.T) {
	// identity-service returns {"account_id": null} when the user has
	// never chosen — the fetcher must project this as "" so the
	// caller's omitempty behaviour drops the claim entirely.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":null}`))
	}))
	defer srv.Close()

	f := identityservice.NewActiveAccountFetcher(srv.URL, srv.Client())
	got, err := f.GetActiveAccount(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("account_id = %q, want empty (null in wire)", got)
	}
}

func TestActiveAccountFetcher_ServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := identityservice.NewActiveAccountFetcher(srv.URL, srv.Client())
	_, err := f.GetActiveAccount(context.Background(), "u-1")
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
}

func TestActiveAccountFetcher_RejectsEmptyUserID(t *testing.T) {
	f := identityservice.NewActiveAccountFetcher("http://ignored", http.DefaultClient)
	_, err := f.GetActiveAccount(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on empty user_id, got nil")
	}
}
