package http

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// ProxyMap holds a pre-built reverse proxy for each route.
type ProxyMap struct {
	proxies map[string]*proxyEntry
}

type proxyEntry struct {
	proxy       *httputil.ReverseProxy
	stripPrefix bool
	pathPrefix  string
}

// NewProxyMap creates a reverse proxy instance for each route at startup.
// Proxies are keyed by path prefix for O(1) lookup after route resolution.
// Returns an error if any route has an unparseable backend URL.
func NewProxyMap(routes []domain.Route) (*ProxyMap, error) {
	proxies := make(map[string]*proxyEntry, len(routes))
	for _, route := range routes {
		target, err := url.Parse(route.Upstream.URL)
		if err != nil {
			return nil, fmt.Errorf("parsing backend URL %q for prefix %q: %w", route.Upstream.URL, route.Match.PathPrefix, err)
		}

		stripPrefix := route.Upstream.StripPrefix != ""
		proxy := &httputil.ReverseProxy{
			Director: newDirector(target, route.Match.PathPrefix, stripPrefix),
		}

		proxies[route.Match.PathPrefix] = &proxyEntry{
			proxy:       proxy,
			stripPrefix: stripPrefix,
			pathPrefix:  route.Match.PathPrefix,
		}
	}
	return &ProxyMap{proxies: proxies}, nil
}

// Get returns the reverse proxy for the given path prefix.
func (pm *ProxyMap) Get(pathPrefix string) (*httputil.ReverseProxy, bool) {
	e, ok := pm.proxies[pathPrefix]
	if !ok {
		return nil, false
	}
	return e.proxy, true
}

// newDirector creates a Director function that rewrites the request URL
// to point at the target backend. This is the core of the reverse proxy:
//
//   - Sets the scheme and host to the backend's address
//   - Optionally strips the gateway path prefix before forwarding
//   - Preserves query parameters from the original request
//   - Sets X-Forwarded-Host so the backend can see the original host
//
// Note: httputil.ReverseProxy automatically appends X-Forwarded-For.
func newDirector(target *url.URL, pathPrefix string, stripPrefix bool) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		if stripPrefix {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, pathPrefix)
			if req.URL.Path == "" || req.URL.Path[0] != '/' {
				req.URL.Path = "/" + req.URL.Path
			}
		}

		// Preserve the original host for the backend to inspect.
		if _, ok := req.Header["X-Forwarded-Host"]; !ok {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
	}
}
