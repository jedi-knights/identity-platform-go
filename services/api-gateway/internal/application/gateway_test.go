//go:build unit

package application_test

import (
	"context"
	"errors"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/testutil"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/application"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// --- fake RouteResolver ---

type fakeResolver struct {
	route *domain.Route
	err   error
}

// Compile-time check: fakeResolver must satisfy ports.RouteResolver.
var _ ports.RouteResolver = (*fakeResolver)(nil)

func (f *fakeResolver) Resolve(_ context.Context, _, _ string, _ map[string]string) (*domain.Route, error) {
	return f.route, f.err
}

// --- tests ---

func TestGatewayService_Route_ReturnsRouteOnSuccess(t *testing.T) {
	want := &domain.Route{Name: "identity", Upstream: domain.UpstreamTarget{URL: "http://identity:8080"}}
	svc := application.NewGatewayService(&fakeResolver{route: want}, testutil.NewTestLogger())

	got, err := svc.Route(context.Background(), "GET", "/api/identity/users", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got route %+v, want %+v", got, want)
	}
}

func TestGatewayService_Route_ReturnsErrorOnNoMatch(t *testing.T) {
	notFound := apperrors.Wrap(apperrors.ErrCodeNotFound, "no route matched", ports.ErrNoRouteMatched)
	svc := application.NewGatewayService(&fakeResolver{err: notFound}, testutil.NewTestLogger())

	_, err := svc.Route(context.Background(), "GET", "/unknown", nil)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsNotFound(err) {
		t.Errorf("expected not-found error, got: %v", err)
	}
	if !errors.Is(err, ports.ErrNoRouteMatched) {
		t.Errorf("expected ErrNoRouteMatched in error chain, got: %v", err)
	}
}

func TestGatewayService_Route_PropagatesInfrastructureError(t *testing.T) {
	infraErr := apperrors.New(apperrors.ErrCodeInternal, "resolver database unavailable")
	svc := application.NewGatewayService(&fakeResolver{err: infraErr}, testutil.NewTestLogger())

	_, err := svc.Route(context.Background(), "GET", "/api", nil)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !apperrors.IsInternal(err) {
		t.Errorf("expected internal error, got: %v", err)
	}
}

func TestGatewayService_Route_PassesAttributesToResolver(t *testing.T) {
	var gotMethod, gotPath string
	var gotHeaders map[string]string

	resolver := &captureResolver{
		captureFunc: func(method, path string, headers map[string]string) {
			gotMethod = method
			gotPath = path
			gotHeaders = headers
		},
		route: &domain.Route{Name: "test"},
	}

	svc := application.NewGatewayService(resolver, testutil.NewTestLogger())
	headers := map[string]string{"X-Version": "v2"}

	if _, err := svc.Route(context.Background(), "POST", "/api/users", headers); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != "POST" {
		t.Errorf("resolver received method %q, want %q", gotMethod, "POST")
	}
	if gotPath != "/api/users" {
		t.Errorf("resolver received path %q, want %q", gotPath, "/api/users")
	}
	if gotHeaders["X-Version"] != "v2" {
		t.Errorf("resolver received headers %v, want X-Version=v2", gotHeaders)
	}
}

func TestGatewayService_ImplementsRequestRouter(t *testing.T) {
	// This test documents and verifies the compile-time interface check
	// on GatewayService — separate from the var _ declaration to make the
	// intent visible to future readers of the test suite.
	var _ ports.RequestRouter = application.NewGatewayService(nil, testutil.NewTestLogger())
}

// captureResolver records the arguments passed to Resolve for assertion.
type captureResolver struct {
	captureFunc func(method, path string, headers map[string]string)
	route       *domain.Route
	err         error
}

var _ ports.RouteResolver = (*captureResolver)(nil)

func (c *captureResolver) Resolve(_ context.Context, method, path string, headers map[string]string) (*domain.Route, error) {
	if c.captureFunc != nil {
		c.captureFunc(method, path, headers)
	}
	return c.route, c.err
}
