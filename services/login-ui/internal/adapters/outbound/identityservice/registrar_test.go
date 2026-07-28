package identityservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/adapters/outbound/identityservice"
	"github.com/ocrosby/identity-platform-go/services/login-ui/internal/ports"
)

func newRegistrar(t *testing.T, handler http.HandlerFunc) *identityservice.Registrar {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return identityservice.NewRegistrar(srv.URL, srv.Client())
}

func TestRegister_ReturnsAccountIDWhenPresent(t *testing.T) {
	// Arrange
	reg := newRegistrar(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/register" || r.Method != http.MethodPost {
			t.Errorf("route = %s %s, want POST /auth/register", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":    "u-1",
			"email":      "u@x.com",
			"name":       "U",
			"account_id": "acc-abc",
		})
	})

	// Act
	got, err := reg.Register(context.Background(), ports.RegisterRequest{
		Email: "u@x.com", Password: "pw", Name: "U",
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != "u-1" || got.AccountID != "acc-abc" {
		t.Errorf("result = %+v, want UserID=u-1 AccountID=acc-abc", got)
	}
}

func TestRegister_NilSafeWhenAccountIDAbsent(t *testing.T) {
	// Arrange — mirrors the E7-S1c fallback path: identity-service was
	// deployed without IDENTITY_ENTITLEMENTS_SERVICE_URL, so the
	// register response omits account_id entirely. login-ui must NOT
	// treat this as failure.
	reg := newRegistrar(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id": "u-1",
			"email":   "u@x.com",
			"name":    "U",
			// no account_id key
		})
	})

	// Act
	got, err := reg.Register(context.Background(), ports.RegisterRequest{
		Email: "u@x.com", Password: "pw", Name: "U",
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccountID != "" {
		t.Errorf("AccountID = %q, want empty (nil-safe absent case)", got.AccountID)
	}
	if got.UserID != "u-1" {
		t.Errorf("UserID = %q, want u-1", got.UserID)
	}
}

func TestRegister_NilSafeWhenAccountIDEmptyString(t *testing.T) {
	// Arrange — identity-service returns account_id: "" explicitly.
	// Same success semantics as the absent case.
	reg := newRegistrar(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":    "u-1",
			"account_id": "",
		})
	})

	// Act
	got, err := reg.Register(context.Background(), ports.RegisterRequest{
		Email: "u@x.com", Password: "pw", Name: "U",
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccountID != "" {
		t.Errorf("AccountID = %q, want empty", got.AccountID)
	}
}

func TestRegister_MapsBadRequest(t *testing.T) {
	// Arrange
	reg := newRegistrar(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	// Act
	_, err := reg.Register(context.Background(), ports.RegisterRequest{})

	// Assert
	if err == nil || !apperrors.IsBadRequest(err) {
		t.Errorf("expected bad-request error, got %v", err)
	}
}

func TestRegister_MapsConflict(t *testing.T) {
	// Arrange
	reg := newRegistrar(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})

	// Act
	_, err := reg.Register(context.Background(), ports.RegisterRequest{
		Email: "dup@x.com", Password: "pw", Name: "D",
	})

	// Assert
	if err == nil || !apperrors.IsConflict(err) {
		t.Errorf("expected conflict error, got %v", err)
	}
}

func TestRegister_MapsUnexpectedStatusToInternal(t *testing.T) {
	// Arrange
	reg := newRegistrar(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	// Act
	_, err := reg.Register(context.Background(), ports.RegisterRequest{
		Email: "u@x.com", Password: "pw", Name: "U",
	})

	// Assert
	if err == nil || !apperrors.IsInternal(err) {
		t.Errorf("expected internal error, got %v", err)
	}
}

func TestRegister_EmptyUserIDIsError(t *testing.T) {
	// Arrange — a 2xx with no user_id is an upstream bug; fail closed
	// so no orphan session is created downstream.
	reg := newRegistrar(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id": "",
		})
	})

	// Act
	_, err := reg.Register(context.Background(), ports.RegisterRequest{
		Email: "u@x.com", Password: "pw", Name: "U",
	})

	// Assert
	if err == nil || !apperrors.IsInternal(err) {
		t.Errorf("expected internal error, got %v", err)
	}
}
