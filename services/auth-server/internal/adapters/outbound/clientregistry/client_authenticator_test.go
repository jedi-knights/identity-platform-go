package clientregistry_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/clientregistry"
)

func TestClientAuthenticator_Authenticate_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clients/validate":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"valid": true})
		case "/clients/my-client":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"client_id":     "my-client",
				"name":          "My Client",
				"scopes":        []string{"read", "write"},
				"redirect_uris": []string{},
				"grant_types":   []string{"client_credentials"},
				"active":        true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	auth := clientregistry.NewClientAuthenticator(srv.URL, srv.Client())
	client, err := auth.Authenticate(context.Background(), "my-client", "my-secret")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client.ID != "my-client" {
		t.Errorf("ID: got %q, want %q", client.ID, "my-client")
	}
	if len(client.Scopes) != 2 {
		t.Errorf("Scopes: got %v, want [read write]", client.Scopes)
	}
}

func TestClientAuthenticator_Authenticate_InvalidCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
	}))
	defer srv.Close()

	auth := clientregistry.NewClientAuthenticator(srv.URL, srv.Client())
	_, err := auth.Authenticate(context.Background(), "my-client", "wrong-secret")
	if err == nil {
		t.Fatal("expected error for invalid credentials, got nil")
	}
}

// TestClientAuthenticator_Authenticate_InvalidCredentials_HTTP401 verifies that
// a 401 from client-registry-service (the new contract) is mapped to ErrCodeUnauthorized,
// not ErrCodeInternal. A 401 is a known credential rejection, not a server failure.
func TestClientAuthenticator_Authenticate_InvalidCredentials_HTTP401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	auth := clientregistry.NewClientAuthenticator(srv.URL, srv.Client())
	_, err := auth.Authenticate(context.Background(), "my-client", "wrong-secret")
	if err == nil {
		t.Fatal("expected error for invalid credentials, got nil")
	}

	var ae *apperrors.AppError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *apperrors.AppError, got %T: %v", err, err)
	}
	if ae.Code() != apperrors.ErrCodeUnauthorized {
		t.Errorf("expected error code %s, got %s", apperrors.ErrCodeUnauthorized, ae.Code())
	}
}

func TestClientAuthenticator_Authenticate_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	auth := clientregistry.NewClientAuthenticator(srv.URL, srv.Client())
	_, err := auth.Authenticate(context.Background(), "my-client", "secret")
	if err == nil {
		t.Fatal("expected error for server error, got nil")
	}
}

func TestClientAuthenticator_Authenticate_ClientNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clients/validate":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"valid": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	auth := clientregistry.NewClientAuthenticator(srv.URL, srv.Client())
	_, err := auth.Authenticate(context.Background(), "ghost-client", "secret")
	if err == nil {
		t.Fatal("expected error when client metadata not found, got nil")
	}
}
