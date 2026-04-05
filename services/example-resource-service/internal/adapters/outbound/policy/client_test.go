package policy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/adapters/outbound/policy"
)

func TestClient_Evaluate_Allowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/evaluate" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"allowed": true, "reason": "role grants access"})
	}))
	defer srv.Close()

	client := policy.New(srv.URL)
	allowed, err := client.Evaluate(context.Background(), "user-1", "resources", "read")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}
}

func TestClient_Evaluate_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"allowed": false, "reason": "no matching policy"})
	}))
	defer srv.Close()

	client := policy.New(srv.URL)
	allowed, err := client.Evaluate(context.Background(), "user-1", "resources", "write")
	if err != nil {
		t.Fatalf("expected no error for denied request, got: %v", err)
	}
	if allowed {
		t.Error("expected allowed=false")
	}
}

func TestClient_Evaluate_ServiceError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := policy.New(srv.URL)
	_, err := client.Evaluate(context.Background(), "user-1", "resources", "read")
	if err == nil {
		t.Fatal("expected error for service error, got nil")
	}
}

func TestClient_Evaluate_SendsCorrectPayload(t *testing.T) {
	var capturedSubjectID, capturedResource, capturedAction string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		capturedSubjectID = req["subject_id"]
		capturedResource = req["resource"]
		capturedAction = req["action"]

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"allowed": true})
	}))
	defer srv.Close()

	client := policy.New(srv.URL)
	_, err := client.Evaluate(context.Background(), "subject-abc", "resources", "write")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedSubjectID != "subject-abc" {
		t.Errorf("subject_id: got %q, want %q", capturedSubjectID, "subject-abc")
	}
	if capturedResource != "resources" {
		t.Errorf("resource: got %q, want %q", capturedResource, "resources")
	}
	if capturedAction != "write" {
		t.Errorf("action: got %q, want %q", capturedAction, "write")
	}
}
