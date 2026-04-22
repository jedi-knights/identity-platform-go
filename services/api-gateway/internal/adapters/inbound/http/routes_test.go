//go:build unit

package http_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	gatewayhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func newRouter(t *testing.T, router ports.RequestRouter, transport ports.UpstreamTransport) http.Handler {
	t.Helper()
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	h := gatewayhttp.NewHandler(router, transport, &fakeMetrics{}, logger)
	return gatewayhttp.NewRouter(h, logger)
}

func TestNewRouter_HealthEndpointReturns200(t *testing.T) {
	r := newRouter(t, &fakeRouter{}, &fakeTransport{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /health: got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestNewRouter_ProxyRouteForwardsRequest(t *testing.T) {
	route := &domain.Route{Name: "svc"}
	transport := &fakeTransport{statusCode: http.StatusOK}
	r := newRouter(t, &fakeRouter{route: route}, transport)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("proxy route: got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestNewRouter_TraceIDHeaderInjected(t *testing.T) {
	route := &domain.Route{Name: "svc"}
	transport := &fakeTransport{statusCode: http.StatusOK}
	r := newRouter(t, &fakeRouter{route: route}, transport)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	r.ServeHTTP(rr, req)

	if rr.Header().Get("X-Trace-ID") == "" {
		t.Error("X-Trace-ID header not set by TraceIDMiddleware")
	}
}

func TestNewRouter_RecoveryMiddlewareCatchesPanic(t *testing.T) {
	panicRouter := &panicRequestRouter{}
	r := newRouter(t, panicRouter, &fakeTransport{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/panic", nil)

	// Must not panic — RecoveryMiddleware catches it and returns 500.
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 after panic recovery, got %d", rr.Code)
	}
}

// panicRequestRouter panics on every Route call to test recovery middleware.
type panicRequestRouter struct{}

var _ ports.RequestRouter = (*panicRequestRouter)(nil)

func (*panicRequestRouter) Route(_ context.Context, _, _ string, _ map[string]string) (*domain.Route, error) {
	panic("deliberate panic for test")
}
