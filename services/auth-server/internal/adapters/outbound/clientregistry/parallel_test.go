package clientregistry_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/outbound/clientregistry"
)

// rendezvousTimeout bounds how long one endpoint waits for the other to be
// reached before the fixture gives up and fails the request.
const rendezvousTimeout = 2 * time.Second

// registryFixture fakes client-registry-service. Each endpoint's handler
// announces its arrival and, when rendezvous is true, waits for the other
// endpoint to arrive too — so a client that calls them one after the other
// deadlocks until the timeout instead of passing by luck.
type registryFixture struct {
	srv            *httptest.Server
	validateStatus int
	getStatus      int
	rendezvous     bool

	validateArrived chan struct{}
	getArrived      chan struct{}
	getCanceled     chan struct{}
	once            [3]sync.Once
}

func newRegistryFixture(t *testing.T, validateStatus, getStatus int, rendezvous bool) *registryFixture {
	t.Helper()
	f := &registryFixture{
		validateStatus:  validateStatus,
		getStatus:       getStatus,
		rendezvous:      rendezvous,
		validateArrived: make(chan struct{}),
		getArrived:      make(chan struct{}),
		getCanceled:     make(chan struct{}),
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *registryFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/clients/validate" {
		f.handleValidate(w)
		return
	}
	f.handleGet(w, r)
}

func (f *registryFixture) handleValidate(w http.ResponseWriter) {
	f.once[0].Do(func() { close(f.validateArrived) })
	if f.rendezvous && !waitFor(f.getArrived) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if f.validateStatus != http.StatusOK {
		w.WriteHeader(f.validateStatus)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"valid": true})
}

func (f *registryFixture) handleGet(w http.ResponseWriter, r *http.Request) {
	f.once[1].Do(func() { close(f.getArrived) })
	if f.rendezvous && !waitFor(f.validateArrived) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if f.getStatus == http.StatusOK {
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "c1", "scopes": []string{"read"}, "active": true})
		return
	}
	// Linger only when a credential rejection is coming, so cancellation of the
	// lookup is observable as a canceled request context.
	if f.validateStatus != http.StatusOK {
		select {
		case <-r.Context().Done():
			f.once[2].Do(func() { close(f.getCanceled) })
		case <-time.After(rendezvousTimeout):
		}
	}
	w.WriteHeader(f.getStatus)
}

func waitFor(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(rendezvousTimeout):
		return false
	}
}

func authCode(t *testing.T, err error) apperrors.ErrorCode {
	t.Helper()
	var ae *apperrors.AppError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *apperrors.AppError, got %T: %v", err, err)
	}
	return ae.Code()
}

func TestAuthenticate_ValidatesAndFetchesMetadataConcurrently(t *testing.T) {
	f := newRegistryFixture(t, http.StatusOK, http.StatusOK, true)
	auth := clientregistry.NewClientAuthenticator(f.srv.URL, f.srv.Client())

	client, err := auth.Authenticate(context.Background(), "c1", "secret")
	if err != nil {
		t.Fatalf("Authenticate: %v (the two registry calls did not overlap)", err)
	}
	if client == nil || client.ID != "c1" {
		t.Fatalf("expected client c1, got %+v", client)
	}
}

func TestAuthenticate_RejectedCredentialsWinOverMetadataOutcome(t *testing.T) {
	for _, tc := range []struct {
		name      string
		getStatus int
	}{
		{"unknown client", http.StatusNotFound},
		{"registry error", http.StatusInternalServerError},
		{"client found", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRegistryFixture(t, http.StatusUnauthorized, tc.getStatus, true)
			auth := clientregistry.NewClientAuthenticator(f.srv.URL, f.srv.Client())

			client, err := auth.Authenticate(context.Background(), "c1", "wrong")

			if err == nil || client != nil {
				t.Fatalf("expected rejection with no client, got client=%+v err=%v", client, err)
			}
			if got := authCode(t, err); got != apperrors.ErrCodeUnauthorized {
				t.Errorf("code = %s, want %s: rejection must not leak whether the client exists", got, apperrors.ErrCodeUnauthorized)
			}
		})
	}
}

func TestAuthenticate_ValidCredentialsSurfaceMetadataFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		getStatus int
		want      apperrors.ErrorCode
	}{
		{"client vanished", http.StatusNotFound, apperrors.ErrCodeNotFound},
		{"registry error", http.StatusInternalServerError, apperrors.ErrCodeInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRegistryFixture(t, http.StatusOK, tc.getStatus, true)
			auth := clientregistry.NewClientAuthenticator(f.srv.URL, f.srv.Client())

			_, err := auth.Authenticate(context.Background(), "c1", "secret")

			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if got := authCode(t, err); got != tc.want {
				t.Errorf("code = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAuthenticate_RejectionCancelsInFlightMetadataLookup(t *testing.T) {
	f := newRegistryFixture(t, http.StatusUnauthorized, http.StatusInternalServerError, true)
	auth := clientregistry.NewClientAuthenticator(f.srv.URL, f.srv.Client())

	if _, err := auth.Authenticate(context.Background(), "c1", "wrong"); err == nil {
		t.Fatal("expected rejection, got nil")
	}

	select {
	case <-f.getCanceled:
	case <-time.After(rendezvousTimeout):
		t.Fatal("metadata lookup was not canceled after credentials were rejected")
	}
}
