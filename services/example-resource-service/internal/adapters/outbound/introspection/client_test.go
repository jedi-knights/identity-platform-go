package introspection_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/introspection"
)

// writeJSON encodes v as JSON to w. Test helper — logs encoding errors.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

func TestClient_Introspect_ActiveToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]any{
			"active":    true,
			"sub":       "client-1",
			"client_id": "client-1",
			"scope":     "read write",
		})
	}))
	defer srv.Close()

	client := introspection.NewClient(srv.URL, srv.Client(), "")
	result, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.Active {
		t.Error("expected active=true")
	}
	if result.Subject != "client-1" {
		t.Errorf("Subject: got %q, want %q", result.Subject, "client-1")
	}
	if result.Scope != "read write" {
		t.Errorf("Scope: got %q, want %q", result.Scope, "read write")
	}
}

func TestClient_Introspect_InactiveToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"active": false})
	}))
	defer srv.Close()

	client := introspection.NewClient(srv.URL, srv.Client(), "")
	result, err := client.Introspect(context.Background(), "expired-token")
	if err != nil {
		t.Fatalf("expected no error for inactive token, got: %v", err)
	}
	if result.Active {
		t.Error("expected active=false for expired token")
	}
}

func TestClient_Introspect_ServiceUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := introspection.NewClient(srv.URL, srv.Client(), "")
	_, err := client.Introspect(context.Background(), "any-token")
	if err == nil {
		t.Fatal("expected error for service unavailable, got nil")
	}
}

func TestClient_Introspect_WithRolesAndPermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"active":      true,
			"sub":         "user-1",
			"client_id":   "client-1",
			"scope":       "read write",
			"roles":       []string{"admin", "viewer"},
			"permissions": []string{"resources:read", "resources:write"},
		})
	}))
	defer srv.Close()

	client := introspection.NewClient(srv.URL, srv.Client(), "")

	t.Run("active", func(t *testing.T) {
		result, err := client.Introspect(context.Background(), "some-token")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.Active {
			t.Error("expected active=true")
		}
	})

	t.Run("roles", func(t *testing.T) {
		result, err := client.Introspect(context.Background(), "some-token")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !slices.Equal(result.Roles, []string{"admin", "viewer"}) {
			t.Errorf("Roles: got %v, want [admin viewer]", result.Roles)
		}
	})

	t.Run("permissions", func(t *testing.T) {
		result, err := client.Introspect(context.Background(), "some-token")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !slices.Equal(result.Permissions, []string{"resources:read", "resources:write"}) {
			t.Errorf("Permissions: got %v, want [resources:read resources:write]", result.Permissions)
		}
	})
}

// TestClient_Introspect_SendsAuthHeaderWhenSecretConfigured verifies that the client
// sends Authorization: Bearer <secret> when a secret is configured (RFC 7662 §2.1).
func TestClient_Introspect_SendsAuthHeaderWhenSecretConfigured(t *testing.T) {
	const secret = "super-secret-key"
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Arrange — capture the header the client sent
		gotAuth = r.Header.Get("Authorization")
		writeJSON(t, w, map[string]any{"active": true, "sub": "s1", "scope": "read"})
	}))
	defer srv.Close()

	// Act
	client := introspection.NewClient(srv.URL, srv.Client(), secret)
	_, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Assert
	want := "Bearer " + secret
	if gotAuth != want {
		t.Errorf("Authorization header = %q, want %q", gotAuth, want)
	}
}

func TestClient_Introspect_NoRolesOrPermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"active":    true,
			"sub":       "client-1",
			"client_id": "client-1",
			"scope":     "read",
		})
	}))
	defer srv.Close()

	client := introspection.NewClient(srv.URL, srv.Client(), "")
	result, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.Roles != nil {
		t.Errorf("Roles: got %v, want nil", result.Roles)
	}
	if result.Permissions != nil {
		t.Errorf("Permissions: got %v, want nil", result.Permissions)
	}
}
