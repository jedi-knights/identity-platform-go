//go:build unit

package reload_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/reload"
)

func makeHandler(body string, status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

// TestAtomicHandler_ServesInitialHandler verifies that requests served before
// any Swap call reach the handler passed to New.
func TestAtomicHandler_ServesInitialHandler(t *testing.T) {
	h := reload.New(makeHandler("initial", http.StatusOK))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.String() != "initial" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "initial")
	}
}

// TestAtomicHandler_SwapServesNewHandler verifies that after Swap, new requests
// are served by the new handler.
func TestAtomicHandler_SwapServesNewHandler(t *testing.T) {
	h := reload.New(makeHandler("v1", http.StatusOK))
	h.Swap(makeHandler("v2", http.StatusAccepted))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusAccepted {
		t.Errorf("status after swap = %d, want %d", rr.Code, http.StatusAccepted)
	}
	if rr.Body.String() != "v2" {
		t.Errorf("body after swap = %q, want %q", rr.Body.String(), "v2")
	}
}

// TestAtomicHandler_MultipleSwapsRetainsLatest verifies that repeated swaps
// leave the handler pointing to the most recently installed handler.
func TestAtomicHandler_MultipleSwapsRetainsLatest(t *testing.T) {
	h := reload.New(makeHandler("v1", http.StatusOK))
	h.Swap(makeHandler("v2", http.StatusOK))
	h.Swap(makeHandler("v3", http.StatusTeapot))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d (last swap not applied)", rr.Code, http.StatusTeapot)
	}
	if rr.Body.String() != "v3" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "v3")
	}
}
