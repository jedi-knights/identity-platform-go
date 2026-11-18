package container

import "net/http"

// maxIdleConnsPerHost sizes the idle-connection pool for each upstream host.
// net/http's default keeps only 2, so any burst of concurrent calls to one
// upstream (e.g. every token request calls client-registry-service twice)
// dials a fresh TCP connection per request once more than 2 are in flight.
// 64 covers the expected concurrency per replica; idle connections still
// expire via the transport's IdleConnTimeout.
const maxIdleConnsPerHost = 64

// outboundTransport returns a clone of http.DefaultTransport with a larger
// per-host idle pool. Cloning keeps the default's proxy, dial, TLS and
// idle-timeout settings and avoids mutating the process-wide transport.
// It falls back to the unmodified default if http.DefaultTransport has been
// replaced with a non-*http.Transport.
func outboundTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	t := base.Clone()
	t.MaxIdleConnsPerHost = maxIdleConnsPerHost
	return t
}
