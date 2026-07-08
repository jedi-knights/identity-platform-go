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

// happyPathHandler asserts the inbound request shape and writes the
// canonical success response. Extracted from TestIssueCodeClient_HappyPath
// to keep its cyclomatic complexity within the project's cap of 7.
func happyPathHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/issue-code" {
			t.Errorf("path = %q, want /internal/issue-code", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer svc-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["login_challenge"] != "ch-1" || body["session_id"] != "user-42" {
			t.Errorf("body = %v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":"code-xyz","redirect_uri":"https://rp.example.com/cb","state":"state-abc","iss":"https://auth.example.com"}`)
	}
}

func TestIssueCodeClient_HappyPath(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(happyPathHandler(t))
	defer srv.Close()
	client := authserver.NewIssueCodeClient(srv.URL, "svc-token", srv.Client())

	// Act
	resp, err := client.IssueCode(context.Background(), ports.IssueCodeRequest{
		LoginChallenge: "ch-1",
		SessionID:      "user-42",
		ConsentGranted: []string{"openid"},
	})

	// Assert
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	if resp.Code != "code-xyz" || resp.RedirectURI != "https://rp.example.com/cb" || resp.State != "state-abc" {
		t.Errorf("resp = %+v", resp)
	}
	if resp.Issuer != "https://auth.example.com" {
		t.Errorf("resp.Issuer = %q, want https://auth.example.com", resp.Issuer)
	}
}

func TestIssueCodeClient_AuthServerErrorMapsToInternal(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
	}))
	defer srv.Close()
	client := authserver.NewIssueCodeClient(srv.URL, "svc-token", srv.Client())

	// Act
	_, err := client.IssueCode(context.Background(), ports.IssueCodeRequest{
		LoginChallenge: "missing",
		SessionID:      "user",
	})

	// Assert
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestIssueCodeClient_EmptyCode_Errors(t *testing.T) {
	// Arrange — defense in depth: a 200 with an empty code is a contract
	// breach upstream and must not be treated as a successful sign-in.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":"","redirect_uri":"https://rp.example.com/cb"}`)
	}))
	defer srv.Close()
	client := authserver.NewIssueCodeClient(srv.URL, "svc-token", srv.Client())

	// Act
	_, err := client.IssueCode(context.Background(), ports.IssueCodeRequest{LoginChallenge: "ch", SessionID: "u"})

	// Assert
	if err == nil {
		t.Fatal("expected error for empty code in 200 response")
	}
}
