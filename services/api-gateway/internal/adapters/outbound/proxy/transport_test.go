//go:build unit

package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// TestTransport_Forward_HopByHopHeadersNotLeakedToUpstream documents the
// security property that switching from Director to Rewrite provides.
//
// The Connection header is a hop-by-hop control mechanism (RFC 9110 §7.6.1).
// A client can abuse it to smuggle gateway-internal headers to upstreams by
// listing them as Connection values (e.g. "Connection: X-Internal-Token").
// With Director the header names listed in Connection were passed through;
// with Rewrite the proxy strips them before our function even runs.
func TestTransport_Forward_HopByHopHeadersNotLeakedToUpstream(t *testing.T) {
	var receivedSecret string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret = r.Header.Get("X-Internal-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	// Client attempts to smuggle X-Internal-Token by declaring it hop-by-hop.
	req.Header.Set("X-Internal-Token", "smuggled-value")
	req.Header.Set("Connection", "X-Internal-Token")

	if err := tr.Forward(rr, req, route("svc", upstream.URL, "")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedSecret != "" {
		t.Errorf("upstream received smuggled hop-by-hop header X-Internal-Token=%q; Rewrite should have stripped it", receivedSecret)
	}
}

// TestTransport_Forward_RouteTimeoutTriggersError verifies that setting
// route.Upstream.Timeout cancels the request when the upstream is slow.
// The proxy writes 502 Bad Gateway on deadline exceeded — same as any
// unreachable upstream — so we verify both the error return and the status code.
func TestTransport_Forward_RouteTimeoutTriggersError(t *testing.T) {
	// Upstream sleeps longer than the route timeout.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(200 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)

	// 10 ms deadline — the upstream takes 200 ms, so it will always expire.
	r := &domain.Route{
		Name:     "slow-svc",
		Upstream: domain.UpstreamTarget{URL: upstream.URL, Timeout: 10 * time.Millisecond},
	}
	err := tr.Forward(rr, req, r)

	if err == nil {
		t.Fatal("expected error for timed-out upstream, got nil")
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("got status %d, want %d (502 on timeout)", rr.Code, http.StatusBadGateway)
	}
}

func TestTransport_ImplementsUpstreamTransport(t *testing.T) {
	var _ ports.UpstreamTransport = proxy.NewTransport(&http.Client{})
}

// --- Header transformation tests ---

func TestTransport_Forward_RequestHeaderSet(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)

	r := &domain.Route{
		Name: "hdr-set",
		Upstream: domain.UpstreamTarget{
			URL: upstream.URL,
			HeaderTransform: domain.HeaderTransform{
				Request: domain.HeaderRules{
					Set: map[string]string{"X-Custom": "injected"},
				},
			},
		},
	}
	if err := tr.Forward(rr, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "injected" {
		t.Errorf("upstream received X-Custom=%q, want %q", got, "injected")
	}
}

func TestTransport_Forward_RequestHeaderAdd_DoesNotOverwrite(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Existing")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Existing", "original")

	r := &domain.Route{
		Name: "hdr-add",
		Upstream: domain.UpstreamTarget{
			URL: upstream.URL,
			HeaderTransform: domain.HeaderTransform{
				Request: domain.HeaderRules{
					Add: map[string]string{"X-Existing": "should-not-overwrite"},
				},
			},
		},
	}
	if err := tr.Forward(rr, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "original" {
		t.Errorf("upstream received X-Existing=%q, want %q (Add must not overwrite)", got, "original")
	}
}

func TestTransport_Forward_RequestHeaderRemove(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Remove-Me")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Remove-Me", "sensitive-value")

	r := &domain.Route{
		Name: "hdr-remove",
		Upstream: domain.UpstreamTarget{
			URL: upstream.URL,
			HeaderTransform: domain.HeaderTransform{
				Request: domain.HeaderRules{
					Remove: []string{"X-Remove-Me"},
				},
			},
		},
	}
	if err := tr.Forward(rr, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("upstream received X-Remove-Me=%q; Remove rule should have stripped it", got)
	}
}

func TestTransport_Forward_ResponseHeaderSet(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)

	r := &domain.Route{
		Name: "resp-hdr-set",
		Upstream: domain.UpstreamTarget{
			URL: upstream.URL,
			HeaderTransform: domain.HeaderTransform{
				Response: domain.HeaderRules{
					Set: map[string]string{"Cache-Control": "no-store"},
				},
			},
		},
	}
	if err := tr.Forward(rr, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("response Cache-Control=%q, want %q", got, "no-store")
	}
}

func TestTransport_Forward_ResponseHeaderRemove(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "secret-framework")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tr := newTransport()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)

	r := &domain.Route{
		Name: "resp-hdr-remove",
		Upstream: domain.UpstreamTarget{
			URL: upstream.URL,
			HeaderTransform: domain.HeaderTransform{
				Response: domain.HeaderRules{
					Remove: []string{"X-Powered-By"},
				},
			},
		},
	}
	if err := tr.Forward(rr, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rr.Header().Get("X-Powered-By"); got != "" {
		t.Errorf("response X-Powered-By=%q; Remove rule should have stripped it", got)
	}
}
