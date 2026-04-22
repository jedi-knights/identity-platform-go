package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Transport implements ports.UpstreamTransport using net/http/httputil.ReverseProxy.
// A shared *http.Client provides connection pooling across all forwarded requests.
type Transport struct {
	client *http.Client
}

// Compile-time check: Transport must satisfy ports.UpstreamTransport.
var _ ports.UpstreamTransport = (*Transport)(nil)

// NewTransport creates a Transport that uses client for upstream HTTP connections.
// Callers should share a single *http.Client across the process lifetime to benefit
// from connection pooling.
func NewTransport(client *http.Client) *Transport {
	return &Transport{client: client}
}

// Forward proxies r to the upstream defined in route and writes the response to w.
//
// It strips route.Upstream.StripPrefix from the request path before forwarding
// and propagates the original Host via X-Forwarded-Host.
//
// If the upstream is unreachable, a 502 Bad Gateway response is written to w and
// the upstream error is returned so the caller can log it. The caller must check
// whether headers were already written before attempting its own error response.
func (t *Transport) Forward(w http.ResponseWriter, r *http.Request, route *domain.Route) error {
	target, err := url.Parse(route.Upstream.URL)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "invalid upstream URL", err)
	}

	// Capture upstream errors so Forward can return them for logging while
	// letting the proxy write the 502 response directly to w.
	var upstreamErr error

	proxy := &httputil.ReverseProxy{
		Director:  makeDirector(target, route),
		Transport: t.client.Transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			upstreamErr = err
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
	return upstreamErr
}

// makeDirector returns a Director function that rewrites the request to target the
// upstream defined by target and route. It:
//   - sets the URL scheme and host to the upstream target
//   - strips route.Upstream.StripPrefix from the request path (if set)
//   - preserves the original Host in X-Forwarded-Host (RFC 7239)
func makeDirector(target *url.URL, route *domain.Route) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		if strip := route.Upstream.StripPrefix; strip != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, strip)
			if req.URL.Path == "" || req.URL.Path[0] != '/' {
				req.URL.Path = "/" + req.URL.Path
			}
		}

		// RFC 7239: preserve the original Host so the upstream can reconstruct
		// the original request URL if needed.
		if _, ok := req.Header["X-Forwarded-Host"]; !ok {
			if req.Host != "" {
				req.Header.Set("X-Forwarded-Host", req.Host)
			}
		}
		req.Host = target.Host
	}
}
