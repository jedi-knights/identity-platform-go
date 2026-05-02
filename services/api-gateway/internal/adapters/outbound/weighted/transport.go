package weighted

import (
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Transport must satisfy ports.UpstreamTransport.
var _ ports.UpstreamTransport = (*Transport)(nil)

// Transport is a ports.UpstreamTransport Decorator that distributes requests
// across the URL pool in route.Upstream.URLs using weighted random selection.
//
// Design: Decorator pattern — Transport wraps an inner UpstreamTransport
// (typically proxy.Transport, possibly wrapped by circuitbreaker.Transport).
// It replaces route.Upstream.URL with the picker's selection on each request
// and delegates the actual forwarding unchanged.
//
// For routes with no weights or uniform weights, Pick degrades to uniform
// random selection, so this transport is a drop-in replacement for
// roundrobin.Transport in deployments that mix weighted and unweighted routes.
type Transport struct {
	inner  ports.UpstreamTransport
	picker *Picker
}

// NewTransport creates a weighted transport that wraps inner.
func NewTransport(inner ports.UpstreamTransport, picker *Picker) *Transport {
	return &Transport{inner: inner, picker: picker}
}

// Forward picks a URL by weighted random selection, shallow-copies the route
// with that URL set as the active target, then delegates to the inner transport.
//
// The route is never mutated in place: UpstreamTarget contains only value types
// so a struct copy is safe and avoids data races with concurrent requests sharing
// the same route definition loaded at startup.
func (t *Transport) Forward(w http.ResponseWriter, r *http.Request, route *domain.Route) error {
	selected := t.picker.Pick(route.Name, route.Upstream.URLs, route.Upstream.Weights)

	modified := *route
	modified.Upstream.URL = selected

	return t.inner.Forward(w, r, &modified)
}
