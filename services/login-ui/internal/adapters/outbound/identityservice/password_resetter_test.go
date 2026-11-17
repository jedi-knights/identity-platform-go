package identityservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/identityservice"
)

// respondWith builds a PasswordResetter against a server that replies with
// status, and records the request it saw.
func respondWith(t *testing.T, status int, gotPath *string, gotBody *map[string]string) *identityservice.PasswordResetter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if gotPath != nil {
			*gotPath = r.URL.Path
		}
		if gotBody != nil {
			_ = json.NewDecoder(r.Body).Decode(gotBody)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return identityservice.NewPasswordResetter(srv.URL, srv.Client())
}

func TestRequestReset_PostsEmailAndSucceedsOn204(t *testing.T) {
	var path string
	var body map[string]string
	pr := respondWith(t, http.StatusNoContent, &path, &body)

	err := pr.RequestReset(context.Background(), "u@example.com")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/auth/request-password-reset" {
		t.Errorf("path = %q, want /auth/request-password-reset", path)
	}
	if body["email"] != "u@example.com" {
		t.Errorf("body = %v, want email=u@example.com", body)
	}
}

func TestRequestReset_MapsUpstreamStatuses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		check  func(error) bool
	}{
		{"400 is bad request", http.StatusBadRequest, apperrors.IsBadRequest},
		{"429 is rate limit", http.StatusTooManyRequests, apperrors.IsRateLimit},
		{"500 is internal", http.StatusInternalServerError, apperrors.IsInternal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := respondWith(t, tc.status, nil, nil)

			err := pr.RequestReset(context.Background(), "u@example.com")

			if err == nil || !tc.check(err) {
				t.Errorf("err = %v, want matching category for %d", err, tc.status)
			}
		})
	}
}

func TestResetPassword_PostsTokenAndNewPasswordAndSucceedsOn200(t *testing.T) {
	var path string
	var body map[string]string
	pr := respondWith(t, http.StatusOK, &path, &body)

	err := pr.ResetPassword(context.Background(), "tok-123", "correct horse battery")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/auth/reset-password" {
		t.Errorf("path = %q, want /auth/reset-password", path)
	}
	if body["token"] != "tok-123" || body["new_password"] != "correct horse battery" {
		t.Errorf("body = %v, want token and new_password forwarded", body)
	}
}

func TestResetPassword_MapsUpstreamStatuses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		check  func(error) bool
	}{
		{"401 is unauthorized (bad or expired token)", http.StatusUnauthorized, apperrors.IsUnauthorized},
		{"400 is bad request (weak password)", http.StatusBadRequest, apperrors.IsBadRequest},
		{"429 is rate limit", http.StatusTooManyRequests, apperrors.IsRateLimit},
		{"500 is internal", http.StatusInternalServerError, apperrors.IsInternal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := respondWith(t, tc.status, nil, nil)

			err := pr.ResetPassword(context.Background(), "tok", "pw-long-enough")

			if err == nil || !tc.check(err) {
				t.Errorf("err = %v, want matching category for %d", err, tc.status)
			}
		})
	}
}

func TestPasswordResetter_TransportFailureIsInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing is listening any more
	pr := identityservice.NewPasswordResetter(srv.URL, srv.Client())

	reqErr := pr.RequestReset(context.Background(), "u@example.com")
	resetErr := pr.ResetPassword(context.Background(), "tok", "pw-long-enough")

	if !apperrors.IsInternal(reqErr) || !apperrors.IsInternal(resetErr) {
		t.Errorf("errors = %v / %v, want internal for transport failure", reqErr, resetErr)
	}
}
