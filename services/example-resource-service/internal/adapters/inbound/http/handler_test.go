package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/testutil"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
)

// fakeResourceService implements lister, getter, and creator for tests.
type fakeResourceService struct {
	resources map[string]*domain.Resource
}

func newFakeResourceService() *fakeResourceService {
	return &fakeResourceService{
		resources: map[string]*domain.Resource{
			"r1": {ID: "r1", Name: "Resource One", Description: "desc"},
		},
	}
}

func (f *fakeResourceService) ListResources(_ context.Context) ([]*domain.Resource, error) {
	result := make([]*domain.Resource, 0, len(f.resources))
	for _, r := range f.resources {
		result = append(result, r)
	}
	return result, nil
}

func (f *fakeResourceService) GetResource(_ context.Context, id string) (*domain.Resource, error) {
	r, ok := f.resources[id]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "resource not found")
	}
	return r, nil
}

func (f *fakeResourceService) CreateResource(_ context.Context, req domain.CreateResourceRequest) (*domain.Resource, error) {
	r := &domain.Resource{ID: "new-id", Name: req.Name, Description: req.Description}
	f.resources[r.ID] = r
	return r, nil
}

// fakePolicyChecker records calls and returns a configurable result.
type fakePolicyChecker struct {
	called   bool
	resource string
	action   string
	allow    bool
	err      error
}

func (f *fakePolicyChecker) Evaluate(_ context.Context, _, resource, action string) (bool, error) {
	f.called = true
	f.resource = resource
	f.action = action
	return f.allow, f.err
}

// injectContext sets up the context values that middleware normally provides.
func injectContext(r *http.Request, permissions []string) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, contextKeySubject, "user-1")
	ctx = context.WithValue(ctx, contextKeyScopes, []string{"read", "write"})
	ctx = context.WithValue(ctx, contextKeyClientID, "client-1")
	if permissions != nil {
		ctx = context.WithValue(ctx, contextKeyPermissions, permissions)
	}
	return r.WithContext(ctx)
}

// TestListResources_LocalPermissions_Allowed verifies that when JWT permissions
// contain "resources:read", the handler serves the request without calling PolicyChecker.
func TestListResources_LocalPermissions_Allowed(t *testing.T) {
	svc := newFakeResourceService()
	policy := &fakePolicyChecker{allow: false} // would deny if called
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), policy)

	r := injectContext(httptest.NewRequest(http.MethodGet, "/resources", nil), []string{"resources:read"})
	w := httptest.NewRecorder()
	h.ListResources(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if policy.called {
		t.Error("policy checker should not be called when JWT permissions are present")
	}
}

// TestListResources_LocalPermissions_Denied verifies that when JWT permissions
// do NOT contain "resources:read", the handler returns 403 without calling PolicyChecker.
func TestListResources_LocalPermissions_Denied(t *testing.T) {
	svc := newFakeResourceService()
	policy := &fakePolicyChecker{allow: true} // would allow if called
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), policy)

	r := injectContext(httptest.NewRequest(http.MethodGet, "/resources", nil), []string{"resources:write"})
	w := httptest.NewRecorder()
	h.ListResources(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
	if policy.called {
		t.Error("policy checker should not be called when JWT permissions are present")
	}
}

// TestListResources_FallbackToPolicy_Allowed verifies that when permissions are absent
// from context, the PolicyChecker is called as fallback.
func TestListResources_FallbackToPolicy_Allowed(t *testing.T) {
	svc := newFakeResourceService()
	policy := &fakePolicyChecker{allow: true}
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), policy)

	// nil permissions — simulates a pre-RBAC token without the permissions claim.
	r := injectContext(httptest.NewRequest(http.MethodGet, "/resources", nil), nil)
	w := httptest.NewRecorder()
	h.ListResources(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if !policy.called {
		t.Error("policy checker should be called when JWT permissions are absent")
	}
	if policy.resource != "resources" || policy.action != "read" {
		t.Errorf("policy called with resource=%q action=%q, want resources/read", policy.resource, policy.action)
	}
}

// TestListResources_FallbackToPolicy_Denied verifies that PolicyChecker denial is respected.
func TestListResources_FallbackToPolicy_Denied(t *testing.T) {
	svc := newFakeResourceService()
	policy := &fakePolicyChecker{allow: false}
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), policy)

	r := injectContext(httptest.NewRequest(http.MethodGet, "/resources", nil), nil)
	w := httptest.NewRecorder()
	h.ListResources(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestListResources_NoPolicyNorPermissions_Allowed verifies that when neither permissions
// nor a PolicyChecker is present, access is allowed (scope-only pre-RBAC behaviour).
func TestListResources_NoPolicyNorPermissions_Allowed(t *testing.T) {
	svc := newFakeResourceService()
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), nil)

	r := injectContext(httptest.NewRequest(http.MethodGet, "/resources", nil), nil)
	w := httptest.NewRecorder()
	h.ListResources(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}

// TestCreateResource_LocalPermissions_Write verifies "resources:write" allows CreateResource.
func TestCreateResource_LocalPermissions_Write(t *testing.T) {
	svc := newFakeResourceService()
	policy := &fakePolicyChecker{allow: false}
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), policy)

	body := strings.NewReader(`{"name":"new","description":"desc"}`)
	r := httptest.NewRequest(http.MethodPost, "/resources", body)
	r.Header.Set("Content-Type", "application/json")
	r = injectContext(r, []string{"resources:write"})
	w := httptest.NewRecorder()
	h.CreateResource(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d — body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if policy.called {
		t.Error("policy checker should not be called when JWT permissions are present")
	}
}

// TestCreateResource_LocalPermissions_ReadOnly verifies "resources:read" denies CreateResource.
func TestCreateResource_LocalPermissions_ReadOnly(t *testing.T) {
	svc := newFakeResourceService()
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), nil)

	body := strings.NewReader(`{"name":"new","description":"desc"}`)
	r := httptest.NewRequest(http.MethodPost, "/resources", body)
	r.Header.Set("Content-Type", "application/json")
	r = injectContext(r, []string{"resources:read"}) // missing write
	w := httptest.NewRecorder()
	h.CreateResource(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestGetResource_LocalPermissions_Denied verifies that a token without "resources:read"
// is rejected without calling PolicyChecker.
func TestGetResource_LocalPermissions_Denied(t *testing.T) {
	svc := newFakeResourceService()
	policy := &fakePolicyChecker{allow: true}
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), policy)

	r := httptest.NewRequest(http.MethodGet, "/resources/r1", nil)
	r.SetPathValue("id", "r1")
	r = injectContext(r, []string{"resources:write"}) // no read permission
	w := httptest.NewRecorder()
	h.GetResource(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusForbidden)
	}
	if policy.called {
		t.Error("policy checker should not be called when JWT permissions are present")
	}
}

// TestGetResource_LocalPermissions_Allowed verifies "resources:read" allows GetResource.
func TestGetResource_LocalPermissions_Allowed(t *testing.T) {
	svc := newFakeResourceService()
	policy := &fakePolicyChecker{allow: false}
	h := NewHandler(svc, svc, svc, testutil.NewTestLogger(), policy)

	r := httptest.NewRequest(http.MethodGet, "/resources/r1", nil)
	r.SetPathValue("id", "r1")
	r = injectContext(r, []string{"resources:read"})
	w := httptest.NewRecorder()
	h.GetResource(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d — body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if policy.called {
		t.Error("policy checker should not be called when JWT permissions are present")
	}

	var res domain.Resource
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if res.ID != "r1" {
		t.Errorf("ID: got %q, want %q", res.ID, "r1")
	}
}
