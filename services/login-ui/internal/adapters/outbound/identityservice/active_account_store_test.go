package identityservice_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/identityservice"
)

func TestActiveAccountStore_GetReturnsAccountID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Requester-User-ID") != "u-1" {
			t.Errorf("missing/wrong requester header: %q", r.Header.Get("X-Requester-User-ID"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":"acc-abc"}`))
	}))
	defer srv.Close()

	s := identityservice.NewActiveAccountStore(srv.URL, srv.Client())
	got, err := s.GetActiveAccount(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "acc-abc" {
		t.Errorf("got %q, want acc-abc", got)
	}
}

func TestActiveAccountStore_GetProjectsNullToEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":null}`))
	}))
	defer srv.Close()

	s := identityservice.NewActiveAccountStore(srv.URL, srv.Client())
	got, err := s.GetActiveAccount(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty (null in wire)", got)
	}
}

func TestActiveAccountStore_SetSendsPutAndSucceedsOn204(t *testing.T) {
	var gotMethod, gotAccountID, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Requester-User-ID")
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		gotAccountID = payload["account_id"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := identityservice.NewActiveAccountStore(srv.URL, srv.Client())
	if err := s.SetActiveAccount(context.Background(), "u-1", "acc-abc"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotAccountID != "acc-abc" {
		t.Errorf("account_id in body = %q, want acc-abc", gotAccountID)
	}
	if gotHeader != "u-1" {
		t.Errorf("requester header = %q, want u-1", gotHeader)
	}
}

func TestActiveAccountStore_SetErrorsOnNon204(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	s := identityservice.NewActiveAccountStore(srv.URL, srv.Client())
	err := s.SetActiveAccount(context.Background(), "u-1", "acc-abc")
	if err == nil {
		t.Fatal("want error on 400, got nil")
	}
}

func TestActiveAccountStore_RejectsEmptyInputs(t *testing.T) {
	s := identityservice.NewActiveAccountStore("http://ignored", http.DefaultClient)
	if _, err := s.GetActiveAccount(context.Background(), ""); err == nil {
		t.Error("Get(\"\") should error")
	}
	if err := s.SetActiveAccount(context.Background(), "", "acc-1"); err == nil {
		t.Error("Set(\"\", ...) should error")
	}
	if err := s.SetActiveAccount(context.Background(), "u-1", ""); err == nil {
		t.Error("Set(..., \"\") should error")
	}
}
