//go:build unit

package policyservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/policyservice"
)

func TestGetSubjectPermissions_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subjects/user-1/permissions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject_id":  "user-1",
			"roles":       []string{"admin"},
			"permissions": []string{"resource:read", "resource:write"},
		})
	}))
	defer srv.Close()

	client := policyservice.New(srv.URL)
	roles, perms, err := client.GetSubjectPermissions(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("GetSubjectPermissions: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", roles)
	}
	if len(perms) != 2 {
		t.Errorf("permissions count = %d, want 2", len(perms))
	}
}

func TestGetSubjectPermissions_NonOKStatus_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := policyservice.New(srv.URL)
	_, _, err := client.GetSubjectPermissions(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}

func TestGetSubjectPermissions_NotFound_ReturnsEmpty(t *testing.T) {
	// 404 means the subject has no policy entry — return empty slices, not an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := policyservice.New(srv.URL)
	roles, perms, err := client.GetSubjectPermissions(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("expected nil error for 404 response, got: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected empty roles, got: %v", roles)
	}
	if len(perms) != 0 {
		t.Errorf("expected empty permissions, got: %v", perms)
	}
}

func TestGetSubjectPermissions_InvalidJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	client := policyservice.New(srv.URL)
	_, _, err := client.GetSubjectPermissions(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error for invalid JSON response, got nil")
	}
}

func TestGetSubjectPermissions_TraversalInSubjectID_PathIsEscaped(t *testing.T) {
	// A subject ID containing "/" must not allow path traversal.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound) // no policy for this subject
	}))
	defer srv.Close()

	client := policyservice.New(srv.URL)
	_, _, _ = client.GetSubjectPermissions(context.Background(), "../admin")
	// The slash must be percent-encoded so the path stays within /subjects/.
	if gotPath == "/subjects/../admin/permissions" {
		t.Errorf("path traversal not prevented: got unescaped path %q", gotPath)
	}
}

func TestGetSubjectPermissions_ServerUnreachable_ReturnsError(t *testing.T) {
	// Point at localhost:1 where nothing listens.
	client := policyservice.New("http://localhost:1")
	_, _, err := client.GetSubjectPermissions(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}
