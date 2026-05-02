//go:build unit

package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/adapters/outbound/proxy"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// TestTransport_TLS_InsecureSkipVerify_ConnectsToTLSServer verifies that a route
// with InsecureSkipVerify=true bypasses certificate validation and connects to a
// TLS server whose self-signed cert would otherwise be rejected.
func TestTransport_TLS_InsecureSkipVerify_ConnectsToTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Default client has no knowledge of the test server's self-signed cert.
	tr := proxy.NewTransport(&http.Client{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := &domain.Route{
		Name: "tls-insecure",
		Upstream: domain.UpstreamTarget{
			URL: srv.URL,
			TLS: domain.TLSConfig{InsecureSkipVerify: true},
		},
	}
	if err := tr.Forward(rr, req, r); err != nil {
		t.Fatalf("unexpected error with InsecureSkipVerify=true: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestTransport_TLS_DefaultClient_RejectsSelfSignedCert verifies that a route
// with zero TLS config uses the default client which rejects the self-signed cert
// used by httptest.NewTLSServer — the proxy returns a transport error.
func TestTransport_TLS_DefaultClient_RejectsSelfSignedCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tr := proxy.NewTransport(&http.Client{}) // no custom TLS trust
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := &domain.Route{
		Name:     "tls-default",
		Upstream: domain.UpstreamTarget{URL: srv.URL},
	}
	err := tr.Forward(rr, req, r)
	if err == nil {
		t.Fatal("expected TLS error for self-signed cert with default client, got nil")
	}
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 on TLS error", rr.Code)
	}
}
