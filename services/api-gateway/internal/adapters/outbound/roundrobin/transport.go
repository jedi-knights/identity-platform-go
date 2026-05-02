package roundrobin

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Transport must satisfy ports.UpstreamTransport.
var _ ports.UpstreamTransport = (*Transport)(nil)

// Transport is a ports.UpstreamTransport Decorator that distributes requests
// across the URL pool defined in route.Upstream.URLs using a URLPicker.
//
// Design: Decorator pattern — Transport wraps an inner UpstreamTransport (typically
// proxy.Transport, possibly already wrapped by circuitbreaker.Transport). It does
// not change the forwarding behaviour; it only replaces route.Upstream.URL with
// the picker's selection before delegating to the inner transport.
//
// The route struct is never mutated in place because it is shared read-only state
// loaded at startup. Instead, Transport creates a shallow copy of the route and
// sets URL on that copy. This is safe because UpstreamTarget contains only value
// types (string, []string, time.Duration); no pointer aliasing issues arise.
type Transport struct {
	inner  ports.UpstreamTransport
	picker ports.URLPicker
}

// NewTransport creates a round-robin transport that wraps inner.
func NewTransport(inner ports.UpstreamTransport, picker ports.URLPicker) *Transport {
	return &Transport{inner: inner, picker: picker}
}

// Forward picks a URL from route.Upstream.URLs, copies the route with that URL
// set as the target, then delegates to the inner transport.
//
// When the route has only one URL (single-upstream configuration), the copy
// carries the same URL as the original — the overhead is one struct copy and
// one function call, both negligible.
func (t *Transport) Forward(w http.ResponseWriter, r *http.Request, route *domain.Route) error {
	selected := t.picker.Pick(route.Name, route.Upstream.URLs)

	// Shallow-copy the route so we can replace URL without touching shared state.
	// UpstreamTarget fields are all value types; the URLs slice header is copied
	// but we do not modify the slice contents, so this is safe.
	modified := *route
	modified.Upstream.URL = selected

	return t.inner.Forward(w, r, &modified)
}
