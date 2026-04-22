//go:build unit

package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/proxy"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func newTransport() *proxy.Transport {
	return proxy.NewTransport(&http.Client{})
}

func route(name, upstreamURL, stripPrefix string) *domain.Route {
	return &domain.Route{
		Name:     name,
		Upstream: domain.UpstreamTarget{URL: upstreamURL, StripPrefix: stripPrefix},
	}
}

func TestTransport_Forward_ProxiesRequestToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)

	err := tr.Forward(rr, req, route("test", upstream.URL, ""))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rr.Body)
	if string(body) != `{"ok":true}`+"\n" && string(body) != `{"ok":true}` {
		t.Errorf("unexpected body: %q", body)
	}
}

func TestTransport_Forward_StripsPathPrefix(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/identity/users/123", nil)

	err := tr.Forward(rr, req, route("identity", upstream.URL, "/api/identity"))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedPath != "/users/123" {
		t.Errorf("upstream received path %q, want %q", receivedPath, "/users/123")
	}
}

func TestTransport_Forward_StripPrefixProducesRootPath(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	// Request path equals the strip prefix exactly — upstream should receive "/".
	req := httptest.NewRequest(http.MethodGet, "/api", nil)

	if err := tr.Forward(rr, req, route("svc", upstream.URL, "/api")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedPath != "/" {
		t.Errorf("upstream received path %q, want %q", receivedPath, "/")
	}
}

func TestTransport_Forward_SetsXForwardedHost(t *testing.T) {
	var receivedHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Host = "gateway.example.com"

	if err := tr.Forward(rr, req, route("svc", upstream.URL, "")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedHeader != "gateway.example.com" {
		t.Errorf("upstream received X-Forwarded-Host %q, want %q", receivedHeader, "gateway.example.com")
	}
}

func TestTransport_Forward_DoesNotOverwriteExistingXForwardedHost(t *testing.T) {
	var receivedHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Forwarded-Host", "original-client.example.com")

	if err := tr.Forward(rr, req, route("svc", upstream.URL, "")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedHeader != "original-client.example.com" {
		t.Errorf("upstream received X-Forwarded-Host %q, want original value", receivedHeader)
	}
}

func TestTransport_Forward_Returns502WhenUpstreamUnreachable(t *testing.T) {
	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)

	err := tr.Forward(rr, req, route("dead", "http://localhost:1", ""))

	if err == nil {
		t.Fatal("expected error for unreachable upstream, got nil")
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadGateway)
	}
}

func TestTransport_Forward_ReturnsErrorForInvalidUpstreamURL(t *testing.T) {
	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)

	err := tr.Forward(rr, req, route("bad-url", "://not-a-url", ""))

	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestTransport_ImplementsUpstreamTransport(t *testing.T) {
	var _ ports.UpstreamTransport = proxy.NewTransport(&http.Client{})
}
