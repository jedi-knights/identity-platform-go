package authserver_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/authserver"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

func TestDeviceDecisionClient_Approve_HappyPath(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/device/decision" {
			t.Errorf("path = %q, want /internal/device/decision", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer svc-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["user_code"] != "ABCD-1234" || body["subject"] != "user-42" || body["approved"] != true {
			t.Errorf("body = %v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"approved"}`)
	}))
	defer srv.Close()
	client := authserver.NewDeviceDecisionClient(srv.URL, "svc-token", srv.Client())

	// Act
	err := client.Decide(context.Background(), ports.DeviceDecisionRequest{
		UserCode: "ABCD-1234",
		Subject:  "user-42",
		Approved: true,
	})

	// Assert
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
}

func TestDeviceDecisionClient_Deny_HappyPath(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["approved"] != false {
			t.Errorf("body = %v, want approved=false", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"denied"}`)
	}))
	defer srv.Close()
	client := authserver.NewDeviceDecisionClient(srv.URL, "svc-token", srv.Client())

	// Act
	err := client.Decide(context.Background(), ports.DeviceDecisionRequest{UserCode: "ABCD-1234", Approved: false})

	// Assert
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
}

func TestDeviceDecisionClient_AuthServerErrorMapsToError(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
	}))
	defer srv.Close()
	client := authserver.NewDeviceDecisionClient(srv.URL, "svc-token", srv.Client())

	// Act
	err := client.Decide(context.Background(), ports.DeviceDecisionRequest{UserCode: "unknown", Approved: true})

	// Assert
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}
