//go:build unit

package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	gatewayhttp "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/application"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// --- fakes ---

type fakeRouter struct {
	route *domain.Route
	err   error
}

var _ ports.RequestRouter = (*fakeRouter)(nil)

func (f *fakeRouter) Route(_ context.Context, _, _ string, _ map[string]string) (*domain.Route, error) {
	return f.route, f.err
}

type fakeTransport struct {
	statusCode int
	body       string
	err        error
}

var _ ports.UpstreamTransport = (*fakeTransport)(nil)

func (f *fakeTransport) Forward(w http.ResponseWriter, _ *http.Request, _ *domain.Route) error {
	if f.statusCode != 0 {
		w.WriteHeader(f.statusCode)
	}
	if f.body != "" {
		_, _ = io.WriteString(w, f.body)
	}
	return f.err
}

type fakeMetrics struct {
	calls []metricsCall
}

type metricsCall struct {
	routeName  string
	statusCode int
	durationMS int64
}

var _ ports.MetricsRecorder = (*fakeMetrics)(nil)

func (f *fakeMetrics) RecordRequest(routeName string, statusCode int, durationMS int64) {
	f.calls = append(f.calls, metricsCall{routeName, statusCode, durationMS})
}

// --- helpers ---

func newHandler(t *testing.T, router ports.RequestRouter, transport ports.UpstreamTransport, metrics ports.MetricsRecorder) *gatewayhttp.Handler {
	t.Helper()
	logger := logging.NewLogger(logging.Config{Output: io.Discard})
	return gatewayhttp.NewHandler(router, transport, metrics, logger)
}

func do(t *testing.T, h http.HandlerFunc, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	h(rr, req)
	return rr
}

// --- Proxy tests ---

func TestHandler_Proxy_Returns404WhenNoRouteMatched(t *testing.T) {
	noMatch := apperrors.Wrap(apperrors.ErrCodeNotFound, "no route matched", application.ErrNoRouteMatched)
	h := newHandler(t, &fakeRouter{err: noMatch}, &fakeTransport{}, &fakeMetrics{})

	rr := do(t, h.Proxy, http.MethodGet, "/unknown")

	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandler_Proxy_Returns500OnRoutingInfrastructureFailure(t *testing.T) {
	infraErr := apperrors.New(apperrors.ErrCodeInternal, "resolver unavailable")
	h := newHandler(t, &fakeRouter{err: infraErr}, &fakeTransport{}, &fakeMetrics{})

	rr := do(t, h.Proxy, http.MethodGet, "/api")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestHandler_Proxy_ForwardsRequestWhenRouteResolved(t *testing.T) {
	route := &domain.Route{Name: "identity", Upstream: domain.UpstreamTarget{URL: "http://identity:8080"}}
	transport := &fakeTransport{statusCode: http.StatusOK, body: `{"data":"ok"}`}
	h := newHandler(t, &fakeRouter{route: route}, transport, &fakeMetrics{})

	rr := do(t, h.Proxy, http.MethodGet, "/api/identity/users")

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandler_Proxy_Returns500WhenTransportFailsAndHeadersNotWritten(t *testing.T) {
	route := &domain.Route{Name: "svc"}
	transport := &fakeTransport{err: errors.New("connection refused")}
	h := newHandler(t, &fakeRouter{route: route}, transport, &fakeMetrics{})

	rr := do(t, h.Proxy, http.MethodGet, "/api")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestHandler_Proxy_DoesNotDoubleWriteWhenTransportAlreadyWroteResponse(t *testing.T) {
	route := &domain.Route{Name: "svc"}
	// Transport writes a 502 and also returns an error — handler must not overwrite.
	transport := &fakeTransport{
		statusCode: http.StatusBadGateway,
		body:       "bad gateway",
		err:        errors.New("upstream unreachable"),
	}
	h := newHandler(t, &fakeRouter{route: route}, transport, &fakeMetrics{})

	rr := do(t, h.Proxy, http.MethodGet, "/api")

	if rr.Code != http.StatusBadGateway {
		t.Errorf("got status %d, want %d (transport response must not be overwritten)", rr.Code, http.StatusBadGateway)
	}
}

func TestHandler_Proxy_RecordsMetricsOnSuccess(t *testing.T) {
	route := &domain.Route{Name: "identity"}
	transport := &fakeTransport{statusCode: http.StatusCreated}
	metrics := &fakeMetrics{}
	h := newHandler(t, &fakeRouter{route: route}, transport, metrics)

	do(t, h.Proxy, http.MethodPost, "/api/identity/users")

	if len(metrics.calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(metrics.calls))
	}
	call := metrics.calls[0]
	if call.routeName != "identity" {
		t.Errorf("metrics routeName = %q, want %q", call.routeName, "identity")
	}
	if call.statusCode != http.StatusCreated {
		t.Errorf("metrics statusCode = %d, want %d", call.statusCode, http.StatusCreated)
	}
}

func TestHandler_Proxy_DoesNotRecordMetricsOnRoutingError(t *testing.T) {
	noMatch := apperrors.Wrap(apperrors.ErrCodeNotFound, "no route matched", application.ErrNoRouteMatched)
	metrics := &fakeMetrics{}
	h := newHandler(t, &fakeRouter{err: noMatch}, &fakeTransport{}, metrics)

	do(t, h.Proxy, http.MethodGet, "/unknown")

	if len(metrics.calls) != 0 {
		t.Errorf("expected no metrics calls on routing error, got %d", len(metrics.calls))
	}
}

func TestHandler_Proxy_PassesHeadersToRouter(t *testing.T) {
	var capturedHeaders map[string]string

	capturingRouter := &capturingRouter{
		captureFunc: func(_ context.Context, _, _ string, headers map[string]string) {
			capturedHeaders = headers
		},
		route: &domain.Route{Name: "svc"},
	}
	h := newHandler(t, capturingRouter, &fakeTransport{statusCode: 200}, &fakeMetrics{})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Version", "v2")
	h.Proxy(rr, req)

	if capturedHeaders["X-Version"] != "v2" {
		t.Errorf("router did not receive X-Version header, got: %v", capturedHeaders)
	}
}

// --- Health tests ---

func TestHandler_Health_Returns200WithStatusOK(t *testing.T) {
	h := newHandler(t, &fakeRouter{}, &fakeTransport{}, &fakeMetrics{})

	rr := do(t, h.Health, http.MethodGet, "/health")

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("health body status = %q, want %q", body["status"], "ok")
	}
}

// --- capturing router helper ---

type capturingRouter struct {
	captureFunc func(ctx context.Context, method, path string, headers map[string]string)
	route       *domain.Route
	err         error
}

var _ ports.RequestRouter = (*capturingRouter)(nil)

func (c *capturingRouter) Route(ctx context.Context, method, path string, headers map[string]string) (*domain.Route, error) {
	if c.captureFunc != nil {
		c.captureFunc(ctx, method, path, headers)
	}
	return c.route, c.err
}
