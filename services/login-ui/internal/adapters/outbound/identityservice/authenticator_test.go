package identityservice_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/identityservice"
)

func TestAuthenticator_VerifyCredentials_Success(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" || r.Method != http.MethodPost {
			t.Errorf("got %s %s, want POST /auth/login", r.Method, r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["email"] != "user@example.com" || body["password"] != "hunter2" {
			t.Errorf("body = %v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"user_id":"u-42","email":"user@example.com","name":"User"}`)
	}))
	defer srv.Close()
	auth := identityservice.NewAuthenticator(srv.URL, srv.Client())

	// Act
	subject, err := auth.VerifyCredentials(context.Background(), "user@example.com", "hunter2")

	// Assert
	if err != nil {
		t.Fatalf("VerifyCredentials: %v", err)
	}
	if subject != "u-42" {
		t.Errorf("subject = %q, want u-42", subject)
	}
}

func TestAuthenticator_VerifyCredentials_Unauthorized(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	auth := identityservice.NewAuthenticator(srv.URL, srv.Client())

	// Act
	_, err := auth.VerifyCredentials(context.Background(), "user@example.com", "wrong")

	// Assert
	if !apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want unauthorized", err)
	}
}

func TestAuthenticator_VerifyCredentials_ServerError(t *testing.T) {
	// Arrange — anything other than 200 / 401 is infrastructure failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	auth := identityservice.NewAuthenticator(srv.URL, srv.Client())

	// Act
	_, err := auth.VerifyCredentials(context.Background(), "user@example.com", "hunter2")

	// Assert
	if err == nil || apperrors.IsUnauthorized(err) {
		t.Errorf("err = %v, want non-unauthorized error", err)
	}
}

func TestAuthenticator_VerifyCredentials_EmptyUserID(t *testing.T) {
	// Arrange — a successful response without a user_id is malformed
	// upstream; refuse to treat it as a sign-in.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"user_id":"","email":"user@example.com"}`)
	}))
	defer srv.Close()
	auth := identityservice.NewAuthenticator(srv.URL, srv.Client())

	// Act
	_, err := auth.VerifyCredentials(context.Background(), "user@example.com", "hunter2")

	// Assert
	if err == nil {
		t.Fatal("expected error for empty user_id")
	}
}
