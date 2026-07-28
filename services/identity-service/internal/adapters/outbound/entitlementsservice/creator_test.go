package entitlementsservice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/entitlementsservice"
)

func newCreator(t *testing.T, handler http.HandlerFunc) *entitlementsservice.Creator {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return entitlementsservice.NewCreator(srv.URL, srv.Client())
}

func TestCreatePersonalAccount_Returns201Payload(t *testing.T) {
	// Arrange
	creator := newCreator(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/personal" {
			t.Errorf("path = %q, want /accounts/personal", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["user_id"] != "u-1" || body["email"] != "u@x.com" {
			t.Errorf("body = %+v, want user_id=u-1 email=u@x.com", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account_id":    "acc-abc",
			"billing_email": "u@x.com",
			"user_id":       "u-1",
			"created":       true,
		})
	})

	// Act
	id, err := creator.CreatePersonalAccount(context.Background(), "u-1", "u@x.com")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "acc-abc" {
		t.Errorf("account_id = %q, want acc-abc", id)
	}
}

func TestCreatePersonalAccount_Handles200IdempotentReplay(t *testing.T) {
	// Arrange
	creator := newCreator(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account_id": "acc-existing",
			"created":    false,
		})
	})

	// Act
	id, err := creator.CreatePersonalAccount(context.Background(), "u-1", "u@x.com")

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "acc-existing" {
		t.Errorf("account_id = %q, want acc-existing", id)
	}
}

func TestCreatePersonalAccount_MapsBadRequest(t *testing.T) {
	// Arrange
	creator := newCreator(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	// Act
	_, err := creator.CreatePersonalAccount(context.Background(), "", "")

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsBadRequest(err) {
		t.Errorf("expected bad-request error, got %v", err)
	}
}

func TestCreatePersonalAccount_MapsUnexpectedStatusToInternal(t *testing.T) {
	// Arrange
	creator := newCreator(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	// Act
	_, err := creator.CreatePersonalAccount(context.Background(), "u-1", "u@x.com")

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsInternal(err) {
		t.Errorf("expected internal error, got %v", err)
	}
}

func TestCreatePersonalAccount_EmptyAccountIDIsError(t *testing.T) {
	// Arrange — a 201/200 with empty account_id is a bug upstream, not
	// a success. The adapter maps it to an internal error so Register
	// fails closed.
	creator := newCreator(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account_id": "",
		})
	})

	// Act
	_, err := creator.CreatePersonalAccount(context.Background(), "u-1", "u@x.com")

	// Assert
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsInternal(err) {
		t.Errorf("expected internal error, got %v", err)
	}
}
