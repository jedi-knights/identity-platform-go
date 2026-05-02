// Package proxy is the outbound adapter that forwards gateway requests to upstream
// services using net/http/httputil.ReverseProxy.
//
// Design: Proxy pattern — Transport stands between the inbound handler and the
// upstream service, handling connection pooling, path rewriting, and error
// translation without the handler needing to know about upstream HTTP details.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Transport must satisfy ports.UpstreamTransport.
var _ ports.UpstreamTransport = (*Transport)(nil)

// upstreamErrKey is the request-context key used to pass the error holder into
// the cached ErrorHandler closure without creating a new closure per request.
type upstreamErrKey struct{}

// upstreamErrHolder is allocated once per Forward call and written by the
// ErrorHandler. Using a pointer stored in the request context makes this safe
// for reuse across cached reverse proxies.
type upstreamErrHolder struct{ err error }

// Transport implements ports.UpstreamTransport using net/http/httputil.ReverseProxy.
//
// Design: ProxyMap pattern — one *httputil.ReverseProxy is built per upstream URL
// on first use and cached in proxies. Subsequent requests to the same URL avoid
// repeated url.Parse and struct allocation on the hot path. The cache is populated
// lazily via sync.Map to avoid requiring routes at construction time and to make
// zero-value Transport safe to embed in tests.
//
// defaultClient provides TCP connection pooling for routes with no custom TLS.
// Routes that configure mTLS or InsecureSkipVerify receive a per-TLS-config client
// cached in tlsClients; these share defaultClient's timeout and pool settings.
type Transport struct {
	defaultClient *http.Client
	tlsClients    sync.Map // key: domain.TLSConfig → *http.Client
	proxies       sync.Map // key: urlAndPrefix → *httputil.ReverseProxy
}

// NewTransport creates a Transport that uses client for upstream HTTP connections.
// Callers should share a single *http.Client across the process lifetime to benefit
// from connection pooling.
func NewTransport(client *http.Client) *Transport {
	return &Transport{defaultClient: client}
}

// Forward proxies r to the upstream defined in route and writes the response to w.
//
// It strips route.Upstream.StripPrefix from the request path before forwarding
// and propagates the original Host via X-Forwarded-Host.
//
// If route.Upstream.Timeout > 0 a per-request deadline is applied via
// context.WithTimeout. The timeout is set per-route so different upstreams
// can have different SLA budgets without sharing the global client timeout.
//
// If the upstream is unreachable, a 502 Bad Gateway response is written to w and
// the upstream error is returned so the caller can log it. The caller must check
// whether headers were already written before attempting its own error response.
//
// Per-route cache TTL: if CacheMiddleware is active it injects a *ports.CacheTTLHolder
// into the request context. When this route has a CacheTTL > 0, Transport writes the
// route-level TTL back to the holder before forwarding, so CacheMiddleware honours
// per-route overrides without any direct dependency between the inbound and outbound
// adapter packages.
func (t *Transport) Forward(w http.ResponseWriter, r *http.Request, route *domain.Route) error {
	// Apply a per-route deadline before any URL work so the timeout budget covers
	// the URL lookup and proxy setup as well as the upstream round-trip.
	if route.Upstream.Timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), route.Upstream.Timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	// Propagate the per-route cache TTL back to CacheMiddleware via the holder
	// it injected into the request context. Zero CacheTTL means use the global default.
	if route.Upstream.CacheTTL > 0 {
		if h, ok := r.Context().Value(ports.CacheTTLKey{}).(*ports.CacheTTLHolder); ok {
			h.TTL = route.Upstream.CacheTTL
		}
	}

	rp, err := t.proxyFor(route)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrCodeInternal, "proxy setup failed", err)
	}

	// Inject a per-request error holder into the context so the shared (cached)
	// ErrorHandler can write the upstream error without closing over a local var.
	holder := new(upstreamErrHolder)
	r = r.WithContext(context.WithValue(r.Context(), upstreamErrKey{}, holder))

	rp.ServeHTTP(w, r)
	return holder.err
}

// proxyFor returns the cached *httputil.ReverseProxy for the route, building and
// caching it on the first call.
//
// Cache key = route.Name + URL + StripPrefix + wsFlag. Including the route name
// ensures that routes with identical upstream URLs but different header transform
// rules always get distinct proxy instances (Rewrite and ModifyResponse closures
// are baked in at construction time and cannot be shared across differing configs).
func (t *Transport) proxyFor(route *domain.Route) (*httputil.ReverseProxy, error) {
	wsFlag := "0"
	if route.Upstream.WebSocket {
		wsFlag = "1"
	}
	cacheKey := route.Name + "\x00" + route.Upstream.URL + "\x00" + route.Upstream.StripPrefix + "\x00" + wsFlag

	if v, ok := t.proxies.Load(cacheKey); ok {
		return v.(*httputil.ReverseProxy), nil
	}

	target, err := url.Parse(route.Upstream.URL)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", route.Upstream.URL, err)
	}

	client, err := t.clientFor(route.Upstream.TLS)
	if err != nil {
		return nil, fmt.Errorf("tls for route %q: %w", route.Name, err)
	}

	rp := &httputil.ReverseProxy{
		// Rewrite replaces the deprecated Director hook. The key security
		// improvement: the proxy strips hop-by-hop headers (Connection, Upgrade,
		// etc.) from the outgoing request BEFORE Rewrite runs. With Director
		// those headers could be smuggled to upstreams via the Connection header
		// (e.g. "Connection: X-Secret" would forward X-Secret downstream).
		Rewrite:      makeRewrite(target, route.Upstream.StripPrefix, route.Upstream.HeaderTransform.Request),
		Transport:    client.Transport,
		ErrorHandler: proxyErrorHandler,
	}

	// FlushInterval: -1 disables response buffering, which is required for
	// WebSocket upgrade handshakes and server-sent events (SSE). For regular
	// HTTP routes buffering is left at the default (flush only on completion)
	// to reduce per-byte overhead.
	if route.Upstream.WebSocket {
		rp.FlushInterval = -1
	}

	if hasHeaderRules(route.Upstream.HeaderTransform.Response) {
		rp.ModifyResponse = makeModifyResponse(route.Upstream.HeaderTransform.Response)
	}

	// LoadOrStore handles the race between two concurrent cache misses for the
	// same key: the second goroutine discards its newly built proxy and reuses
	// the one already stored by the first. Both proxies would be equivalent, but
	// sharing one avoids a duplicate allocation on the startup burst.
	actual, _ := t.proxies.LoadOrStore(cacheKey, rp)
	return actual.(*httputil.ReverseProxy), nil
}

// clientFor returns the *http.Client to use for the given TLS config.
// Zero-value TLSConfig returns defaultClient. Non-zero configs get a per-config
// client cached in tlsClients so custom TLS settings are applied consistently
// across all requests to the same upstream without re-allocating on every call.
func (t *Transport) clientFor(tlsCfg domain.TLSConfig) (*http.Client, error) {
	if tlsCfg.IsZero() {
		return t.defaultClient, nil
	}
	if v, ok := t.tlsClients.Load(tlsCfg); ok {
		return v.(*http.Client), nil
	}
	client, err := buildTLSClient(t.defaultClient, tlsCfg)
	if err != nil {
		return nil, err
	}
	actual, _ := t.tlsClients.LoadOrStore(tlsCfg, client)
	return actual.(*http.Client), nil
}

// buildTLSClient creates a new *http.Client based on base with TLS settings from cfg.
// If base uses an *http.Transport its connection-pool settings are cloned; otherwise
// a transport with sane defaults is created.
func buildTLSClient(base *http.Client, cfg domain.TLSConfig) (*http.Client, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	if baseTrans, ok := base.Transport.(*http.Transport); ok {
		cloned := baseTrans.Clone()
		cloned.TLSClientConfig = tlsCfg
		return &http.Client{Timeout: base.Timeout, Transport: cloned}, nil
	}
	trans := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		TLSClientConfig:     tlsCfg,
	}
	return &http.Client{Timeout: base.Timeout, Transport: trans}, nil
}

// buildTLSConfig constructs a *tls.Config from the domain TLS settings.
func buildTLSConfig(cfg domain.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in only
	}
	if cfg.CAFile != "" {
		if err := loadCA(tlsCfg, cfg.CAFile); err != nil {
			return nil, err
		}
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if err := loadCert(tlsCfg, cfg.CertFile, cfg.KeyFile); err != nil {
			return nil, err
		}
	}
	return tlsCfg, nil
}

func loadCA(tlsCfg *tls.Config, caFile string) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("proxy: read CA file %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("proxy: no valid certificates in CA file %q", caFile)
	}
	tlsCfg.RootCAs = pool
	return nil
}

func loadCert(tlsCfg *tls.Config, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("proxy: load cert/key (%q, %q): %w", certFile, keyFile, err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

// proxyErrorHandler is the shared ErrorHandler for all cached reverse proxies.
// It reads the per-request error holder injected by Forward so that the upstream
// error is available to the caller without requiring a new closure per request.
var proxyErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
	if h, ok := r.Context().Value(upstreamErrKey{}).(*upstreamErrHolder); ok {
		h.err = err
	}
	http.Error(w, "bad gateway", http.StatusBadGateway)
}

// makeRewrite returns a Rewrite function for httputil.ReverseProxy.
//
// Rewrite is the Go 1.20+ successor to Director. It runs after the proxy has
// already removed hop-by-hop headers from the outgoing request, so they can
// never be forwarded to upstreams regardless of what the client sends.
//
// pr.In is the original inbound request (read-only).
// pr.Out is the outgoing request to the upstream (mutable).
func makeRewrite(target *url.URL, stripPrefix string, reqRules domain.HeaderRules) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		// SetURL rewrites pr.Out to target the upstream: it sets the URL scheme
		// and host from target, then joins the incoming path onto the target path.
		pr.SetURL(target)

		// Strip the configured path prefix before forwarding.
		// After SetURL, pr.Out.URL.Path is the full incoming path.
		// RawPath is cleared to avoid a mismatch with the rewritten Path.
		if stripPrefix != "" {
			pr.Out.URL.Path = strings.TrimPrefix(pr.Out.URL.Path, stripPrefix)
			if pr.Out.URL.Path == "" || pr.Out.URL.Path[0] != '/' {
				pr.Out.URL.Path = "/" + pr.Out.URL.Path
			}
			pr.Out.URL.RawPath = ""
		}

		// The Rewrite hook clears X-Forwarded-Host from pr.Out.Header before we
		// run (see: net/http/httputil.ReverseProxy docs). We must read from
		// pr.In to know what the client originally sent.
		//
		// If the client already set X-Forwarded-Host (they are behind another
		// proxy), preserve their value. Otherwise set it from pr.In.Host so
		// upstreams can reconstruct the original request URL (RFC 7239).
		if fwdHost, ok := pr.In.Header["X-Forwarded-Host"]; ok && len(fwdHost) > 0 {
			pr.Out.Header["X-Forwarded-Host"] = fwdHost
		} else if pr.In.Host != "" {
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		}

		// SetURL sets pr.Out.Host = "" so the HTTP client derives the Host header
		// from the URL. We set it explicitly to make the intent visible: all
		// requests to this upstream carry the upstream's host, not the gateway's.
		pr.Out.Host = target.Host

		// Apply per-route request header rules after all built-in rewrites so
		// operators can overwrite or remove any header, including those set above.
		applyHeaderRules(pr.Out.Header, reqRules)
	}
}

// makeModifyResponse returns a ModifyResponse hook that applies response header
// rules before the proxy returns the upstream response to the client.
func makeModifyResponse(rules domain.HeaderRules) func(*http.Response) error {
	return func(resp *http.Response) error {
		applyHeaderRules(resp.Header, rules)
		return nil
	}
}

// applyHeaderRules applies header manipulation operations in the order that
// produces the most intuitive result: Remove first (eliminate unwanted headers),
// then Set (establish the desired value), then Add (supplement without clobbering).
func applyHeaderRules(h http.Header, rules domain.HeaderRules) {
	for _, k := range rules.Remove {
		h.Del(k)
	}
	for k, v := range rules.Set {
		h.Set(k, v)
	}
	for k, v := range rules.Add {
		if h.Get(k) == "" {
			h.Set(k, v)
		}
	}
}

// hasHeaderRules reports whether any rule in rules is non-empty.
func hasHeaderRules(rules domain.HeaderRules) bool {
	return len(rules.Add)+len(rules.Set)+len(rules.Remove) > 0
}
