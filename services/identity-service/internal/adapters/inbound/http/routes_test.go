package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jedi-knights/go-platform/testutil"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// TestNewRouter_UserClaimsRoute_ReachableViaRouter proves GET
// /users/{id}/claims is actually wired into NewRouter's mux — every other
// GetUserClaims test in handler_test.go calls h.GetUserClaims directly,
// bypassing route registration entirely, so a route that was never added
// to the mux would still show all those tests green.
func TestNewRouter_UserClaimsRoute_ReachableViaRouter(t *testing.T) {
	claims := &fakeClaims{resp: &domain.UserClaims{Subject: "u-1"}}
	h := NewHandler(&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{}, claims, testutil.NewTestLogger())
	router := NewRouter(h, testutil.NewTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/users/u-1/claims", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /users/u-1/claims via router: status = %d, want %d", w.Code, http.StatusOK)
	}
}
