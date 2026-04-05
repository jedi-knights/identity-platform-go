package identityservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/identityservice"
)

func TestUserAuthenticator_VerifyCredentials_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"user_id": "user-42",
			"email":   "alice@example.com",
			"name":    "Alice",
		})
	}))
	defer srv.Close()

	auth := identityservice.NewUserAuthenticator(srv.URL, srv.Client())
	userID, err := auth.VerifyCredentials(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if userID != "user-42" {
		t.Errorf("userID: got %q, want %q", userID, "user-42")
	}
}

func TestUserAuthenticator_VerifyCredentials_InvalidCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	auth := identityservice.NewUserAuthenticator(srv.URL, srv.Client())
	_, err := auth.VerifyCredentials(context.Background(), "alice@example.com", "wrong")
	if err == nil {
		t.Fatal("expected error for invalid credentials, got nil")
	}
}

func TestUserAuthenticator_VerifyCredentials_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	auth := identityservice.NewUserAuthenticator(srv.URL, srv.Client())
	_, err := auth.VerifyCredentials(context.Background(), "alice@example.com", "password")
	if err == nil {
		t.Fatal("expected error for server error, got nil")
	}
}
