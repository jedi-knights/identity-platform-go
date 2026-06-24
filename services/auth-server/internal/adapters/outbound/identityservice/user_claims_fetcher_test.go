package identityservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/identityservice"
)

func TestUserClaimsFetcher_Success(t *testing.T) {
	updated := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/u-1/claims" {
			t.Errorf("path = %q, want /users/u-1/claims", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":            "u-1",
			"email":          "alice@example.com",
			"email_verified": true,
			"name":           "Alice",
			"updated_at":     updated.Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)
	f := identityservice.NewUserClaimsFetcher(srv.URL, srv.Client())

	got, err := f.GetUserClaims(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("GetUserClaims: %v", err)
	}
	if got.Subject != "u-1" || got.Email != "alice@example.com" || !got.EmailVerified || got.Name != "Alice" {
		t.Errorf("got = %+v", got)
	}
	if got.UpdatedAt != updated.Unix() {
		t.Errorf("UpdatedAt = %d, want %d", got.UpdatedAt, updated.Unix())
	}
}

func TestUserClaimsFetcher_NotFoundMapsToErrCodeNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	f := identityservice.NewUserClaimsFetcher(srv.URL, srv.Client())

	_, err := f.GetUserClaims(context.Background(), "u-bogus")
	if !apperrors.IsNotFound(err) {
		t.Errorf("err = %v, want apperrors.IsNotFound true", err)
	}
}

func TestUserClaimsFetcher_ServerErrorIsInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	f := identityservice.NewUserClaimsFetcher(srv.URL, srv.Client())

	_, err := f.GetUserClaims(context.Background(), "u-1")
	if err == nil {
		t.Fatal("expected error for 500 from identity-service")
	}
}

func TestUserClaimsFetcher_EmptySubject(t *testing.T) {
	f := identityservice.NewUserClaimsFetcher("http://unused", http.DefaultClient)
	_, err := f.GetUserClaims(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty subject")
	}
}
