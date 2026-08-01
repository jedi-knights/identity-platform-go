package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jedi-knights/go-platform/testutil"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// newRouterUnderTest builds a Router wired with default fakes — every route
// reachability test uses this to isolate the mux from handler internals.
func newRouterUnderTest() http.Handler {
	h := NewHandler(
		&fakeAuthenticator{}, &fakeRegistrar{}, &fakeVerifier{},
		&fakeClaims{resp: &domain.UserClaims{Subject: "u-1"}},
		&fakePreferences{},
		testutil.NewTestLogger(),
	)
	return NewRouter(h, testutil.NewTestLogger())
}

// TestNewRouter_UserClaimsRoute_ReachableViaRouter proves GET
// /users/{id}/claims is actually wired into NewRouter's mux — every other
// GetUserClaims test in handler_test.go calls h.GetUserClaims directly,
// bypassing route registration entirely, so a route that was never added
// to the mux would still show all those tests green.
func TestNewRouter_UserClaimsRoute_ReachableViaRouter(t *testing.T) {
	router := newRouterUnderTest()

	req := httptest.NewRequest(http.MethodGet, "/users/u-1/claims", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /users/u-1/claims via router: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestNewRouter_GetActiveAccountRoute_ReachableViaRouter proves GET
// /users/{id}/active-account is wired into the mux (E7-S3a). The handler-
// level tests exercise the handler directly, so a missing route
// registration would slip past them.
func TestNewRouter_GetActiveAccountRoute_ReachableViaRouter(t *testing.T) {
	router := newRouterUnderTest()

	req := httptest.NewRequest(http.MethodGet, "/users/u-1/active-account", nil)
	req.Header.Set(requesterHeader, "u-1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /users/u-1/active-account via router: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestNewRouter_SetActiveAccountRoute_ReachableViaRouter proves PUT
// /users/{id}/active-account is wired into the mux (E7-S3a).
func TestNewRouter_SetActiveAccountRoute_ReachableViaRouter(t *testing.T) {
	router := newRouterUnderTest()

	req := httptest.NewRequest(http.MethodPut, "/users/u-1/active-account",
		strings.NewReader(`{"account_id":"acc-1"}`))
	req.Header.Set(requesterHeader, "u-1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT /users/u-1/active-account via router: status = %d, want %d", w.Code, http.StatusNoContent)
	}
}
