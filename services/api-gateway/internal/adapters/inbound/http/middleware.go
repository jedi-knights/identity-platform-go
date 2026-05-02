package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// isValidUUID reports whether s is a well-formed UUID v4 (lowercase hex, RFC 4122).
// Hyphen positions: 8, 13, 18, 23. Version nibble at position 14 must be '4'.
// Variant nibble at position 19 must be one of [89ab].
// Hand-rolled to avoid a regexp allocation and per-call DFA traversal on the hot path.
func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		if !isValidUUIDChar(i, s[i]) {
			return false
		}
	}
	return true
}

func isValidUUIDChar(i int, c byte) bool {
	switch i {
	case 8, 13, 18, 23:
		return c == '-'
	case 14:
		return c == '4'
	case 19:
		return isVariantNibble(c)
	default:
		return isHexByte(c)
	}
}

func isVariantNibble(c byte) bool {
	return c == '8' || c == '9' || c == 'a' || c == 'b'
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// responseBuffer is a minimal http.ResponseWriter that captures status, headers,
// and body for use in CacheMiddleware. It replaces httptest.ResponseRecorder to
// avoid a test-package dependency in production code.
type responseBuffer struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func newResponseBuffer() *responseBuffer {
	return &responseBuffer{header: make(http.Header), code: http.StatusOK}
}

func (rb *responseBuffer) Header() http.Header         { return rb.header }
func (rb *responseBuffer) WriteHeader(code int)        { rb.code = code }
func (rb *responseBuffer) Write(b []byte) (int, error) { return rb.body.Write(b) }

func (rb *responseBuffer) reset() {
	clear(rb.header)
	rb.body.Reset()
	rb.code = http.StatusOK
}

// cacheBufferPool reuses responseBuffer allocations across cache misses.
var cacheBufferPool = sync.Pool{
	New: func() any { return newResponseBuffer() },
}

// RequestIDMiddleware generates or accepts a correlation ID for every request.
//
// Design: Decorator pattern — adds request tracing identity as a cross-cutting
// concern without any handler knowing about X-Request-ID.
//
// Behaviour:
//  1. If the inbound X-Request-ID header is a valid UUID v4, accept it.
//     This allows clients (or upstream proxies) to correlate their own requests
//     with gateway log entries without gateway-generated IDs overwriting theirs.
//  2. If the header is absent, empty, or not a UUID v4, generate a fresh one.
//     This prevents log injection via crafted header values.
//  3. Store the request ID in the request context so LoggingMiddleware and
//     handlers can read it without depending on the raw header.
//  4. Echo the final request ID on the response as X-Request-ID so clients can
//     use it for support tickets / distributed log correlation.
//  5. Forward it to upstreams via the request header (LoggingMiddleware already
//     propagated it to the header; the proxy transport copies it automatically).
func RequestIDMiddleware(logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if !isValidUUID(requestID) {
				// Generate a fresh UUID v4; log if the entropy source is broken.
				var err error
				requestID, err = newRequestID()
				if err != nil {
					logger.Error("failed to generate request ID", "error", err)
					requestID = "00000000-0000-4000-8000-000000000000"
				}
			}

			// Store in context so inner middleware (e.g. LoggingMiddleware) can
			// include it in structured log output without reading the header.
			ctx := logging.WithRequestID(r.Context(), requestID)
			r = r.WithContext(ctx)

			// Set the header on the request so it propagates to upstreams via
			// the reverse proxy (proxy transport copies all non-hop-by-hop headers).
			r.Header.Set("X-Request-ID", requestID)

			// Echo the request ID on the response so clients can use it for support.
			w.Header().Set("X-Request-ID", requestID)

			next.ServeHTTP(w, r)
		})
	}
}

// newRequestID generates a random UUID v4.
// This mirrors libs/httputil.newUUID but returns an error instead of panicking,
// which is appropriate for middleware that can fall back to a sentinel value.
func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("newRequestID: crypto/rand unavailable: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// CORSMiddleware returns middleware that handles CORS preflight and response headers.
//
// For preflight (OPTIONS) requests, it writes the CORS headers and returns 204.
// For all other requests, it adds CORS response headers and delegates to the next handler.
//
// Access-Control-Allow-Origin is set dynamically per request: the incoming Origin
// header is compared against the configured allow-list and echoed back only on a
// match. This is required by the CORS spec — the header accepts a single origin or
// "*", not a comma-separated list.
func CORSMiddleware(cfg config.CORSConfig) func(http.Handler) http.Handler {
	allowedOrigins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowedOrigins[o] = struct{}{}
	}
	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAgeSecs)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if origin := r.Header.Get("Origin"); origin != "" {
				if _, ok := allowedOrigins[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					// Vary: Origin tells caches that the response differs by origin,
					// preventing a cached CORS response for origin A from being
					// served to origin B.
					w.Header().Add("Vary", "Origin")
				}
			}

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", methods)
				w.Header().Set("Access-Control-Allow-Headers", headers)
				w.Header().Set("Access-Control-Max-Age", maxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware returns middleware that enforces per-client rate limiting.
//
// The client key is derived using keySource (see extractClientKey). When a client
// exceeds the limit a 429 Too Many Requests response is returned with Retry-After.
func RateLimitMiddleware(limiter ports.RateLimiter, keySource string, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := extractClientKey(r, keySource)

			if !limiter.Allow(key) {
				logger.Warn("rate limit exceeded", "key", key, "path", r.URL.Path)
				w.Header().Set("Retry-After", "1")
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeRateLimit, "rate limit exceeded"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ConcurrencyMiddleware returns middleware that limits the number of simultaneous
// in-flight requests per client key. When the concurrency limit is reached the
// middleware responds with 503 Service Unavailable and does not forward the request.
//
// The slot is released via defer so it is freed even if the handler panics
// (the recovery middleware above this in the chain will catch the panic after
// the defer runs).
func ConcurrencyMiddleware(limiter ports.ConcurrencyLimiter, keySource string, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := extractClientKey(r, keySource)

			if !limiter.Acquire(key) {
				logger.Warn("concurrency limit reached", "key", key, "path", r.URL.Path)
				w.Header().Set("Retry-After", "1")
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnavailable, "too many concurrent requests"))
				return
			}
			defer limiter.Release(key)

			next.ServeHTTP(w, r)
		})
	}
}

// IPFilterMiddleware returns middleware that allows or blocks requests based on
// the client's IP address and the configured CIDR list.
//
// Mode "allow": only IPs matching a CIDR pass; all others receive 403.
// Mode "deny":  IPs matching a CIDR are blocked with 403; all others pass.
//
// CIDRs are parsed once at construction time so the hot path is just net.IP
// membership checks with no allocation.
func IPFilterMiddleware(cfg config.IPFilterConfig, logger logging.Logger) func(http.Handler) http.Handler {
	nets := parseCIDRs(cfg.CIDRs, logger)
	allow := strings.EqualFold(cfg.Mode, "allow")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := extractClientKey(r, cfg.KeySource)
			ip := net.ParseIP(key)

			matched := ip != nil && matchesCIDR(ip, nets)

			// allow-list: block if NOT in any CIDR
			// deny-list:  block if IN any CIDR
			blocked := (allow && !matched) || (!allow && matched)

			if blocked {
				logger.Warn("ip filter blocked", "ip", key, "mode", cfg.Mode, "path", r.URL.Path)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "forbidden"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CompressionMiddleware returns middleware that gzip-compresses responses for
// clients that advertise Accept-Encoding: gzip.
//
// Compression is applied only when:
//   - The client sent Accept-Encoding containing "gzip"
//   - The response Content-Type is compressible (text/*, application/json, application/xml)
//   - The response body is at least cfg.MinSizeBytes (avoids wasting CPU on tiny payloads)
//   - The upstream did not already set Content-Encoding (no double-compression)
func CompressionMiddleware(cfg config.CompressionConfig, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}
			grw := newGzipResponseWriter(w, cfg.Level, cfg.MinSizeBytes, logger)
			defer grw.finish()
			next.ServeHTTP(grw, r)
		})
	}
}

// CacheMiddleware returns middleware that caches upstream responses in memory.
//
// Design: Decorator pattern — wraps the next handler and adds response caching
// as a cross-cutting concern. Only GET and HEAD requests are cached; POST, PUT,
// DELETE, and PATCH bypass the cache unconditionally.
//
// Cache key: method + path + query + Accept header. Responses are stored only
// when the upstream returns 200 OK. The cached status, headers, and body are
// replayed exactly on subsequent hits.
//
// Per-route TTL override: proxy.Transport writes the route's CacheTTL back to a
// *ports.CacheTTLHolder injected into the request context here. If no per-route
// TTL was set, the holder retains the global defaultTTL from cfg.DefaultTTLSecs.
func CacheMiddleware(cache ports.ResponseCache, cfg config.CacheConfig) func(http.Handler) http.Handler {
	defaultTTL := time.Duration(cfg.DefaultTTLSecs) * time.Second
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isCacheableMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			key := buildCacheKey(r)
			if entry, ok := cache.Get(key); ok {
				writeCachedEntry(w, entry)
				return
			}
			holder := &ports.CacheTTLHolder{TTL: defaultTTL}
			r = r.WithContext(context.WithValue(r.Context(), ports.CacheTTLKey{}, holder))
			rec := cacheBufferPool.Get().(*responseBuffer)
			rec.reset()
			next.ServeHTTP(rec, r)
			if rec.code == http.StatusOK {
				cache.Set(key, captureEntry(rec), holder.TTL)
			}
			flushRecorder(w, rec)
			cacheBufferPool.Put(rec)
		})
	}
}

func isCacheableMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func buildCacheKey(r *http.Request) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte(0)
	b.WriteString(r.URL.Path)
	b.WriteByte(0)
	b.WriteString(r.URL.RawQuery)
	b.WriteByte(0)
	b.WriteString(r.Header.Get("Accept"))
	return b.String()
}

func writeCachedEntry(w http.ResponseWriter, entry *ports.CacheEntry) {
	for k, vs := range entry.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(entry.StatusCode)
	_, _ = w.Write(entry.Body) // headers already committed; write errors cannot be remediated
}

func captureEntry(rec *responseBuffer) *ports.CacheEntry {
	// bytes.Clone copies the body out of the buffer so it is safe to return
	// the buffer to the pool and reuse it for the next request.
	return &ports.CacheEntry{
		StatusCode: rec.code,
		Header:     rec.header.Clone(),
		Body:       bytes.Clone(rec.body.Bytes()),
	}
}

func flushRecorder(w http.ResponseWriter, rec *responseBuffer) {
	for k, vs := range rec.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.code)
	_, _ = io.Copy(w, &rec.body) // headers already committed; copy errors cannot be remediated
}

// --- client key extraction ---

// extractClientKey derives a rate-limit or IP-filter key from the request
// based on keySource. Falls back to the raw IP from RemoteAddr for any
// source that returns an empty value.
//
// keySource values:
//   - "ip"              — RemoteAddr (default)
//   - "x-forwarded-for" — first IP in X-Forwarded-For header
//   - "x-real-ip"       — X-Real-IP header
//   - "header:<name>"   — named header value
//   - "jwt-subject"     — X-Auth-Subject injected by JWTMiddleware
func extractClientKey(r *http.Request, keySource string) string {
	ip := extractIP(r.RemoteAddr)
	switch keySource {
	case "", "ip":
		return ip
	case "x-forwarded-for":
		return keyFromXFF(r, ip)
	case "x-real-ip":
		return keyFromHeader(r, "X-Real-IP", ip)
	case "jwt-subject":
		return keyFromHeader(r, "X-Auth-Subject", ip)
	default:
		if strings.HasPrefix(keySource, "header:") {
			return keyFromHeader(r, strings.TrimPrefix(keySource, "header:"), ip)
		}
		return ip
	}
}

func keyFromXFF(r *http.Request, fallback string) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may be a comma-separated list; the first entry is the
		// original client IP (subsequent entries are proxies).
		if first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); first != "" {
			return first
		}
	}
	return fallback
}

func keyFromHeader(r *http.Request, name, fallback string) string {
	if v := r.Header.Get(name); v != "" {
		return v
	}
	return fallback
}

// extractIP strips the port from RemoteAddr to get the client IP.
func extractIP(remoteAddr string) string {
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}
	return remoteAddr
}

// parseCIDRs parses CIDR strings at construction time. Invalid entries are
// logged and skipped so a misconfiguration doesn't disable the filter entirely.
func parseCIDRs(cidrs []string, logger logging.Logger) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			logger.Warn("ip_filter: invalid CIDR skipped", "cidr", c, "error", err)
			continue
		}
		nets = append(nets, ipnet)
	}
	return nets
}

// matchesCIDR reports whether ip falls within any of the given networks.
func matchesCIDR(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// --- gzip response writer ---

// gzipResponseWriter buffers the response until it knows both the Content-Type
// and the body size. Once the buffer crosses MinSizeBytes and the Content-Type
// is compressible it arms the gzip writer; otherwise it flushes plain.
type gzipResponseWriter struct {
	http.ResponseWriter
	logger       logging.Logger
	level        int
	minSizeBytes int
	buf          []byte
	status       int
	gz           *gzip.Writer
	headersDone  bool // true after WriteHeader has been called on the real writer
}

func newGzipResponseWriter(w http.ResponseWriter, level, minSizeBytes int, logger logging.Logger) *gzipResponseWriter {
	if level < gzip.BestSpeed || level > gzip.BestCompression {
		level = gzip.DefaultCompression
	}
	return &gzipResponseWriter{
		ResponseWriter: w,
		logger:         logger,
		level:          level,
		minSizeBytes:   minSizeBytes,
		status:         http.StatusOK,
	}
}

func (g *gzipResponseWriter) WriteHeader(status int) {
	g.status = status
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if g.headersDone {
		return g.writeThrough(b)
	}
	g.buf = append(g.buf, b...)
	return len(b), nil
}

func (g *gzipResponseWriter) finish() {
	if g.headersDone {
		if g.gz != nil {
			if err := g.gz.Close(); err != nil {
				// Headers already committed; status cannot change. Log so operators
				// know the client received a truncated or corrupt gzip stream.
				g.logger.Error("gzip: failed to close compressed stream", "error", err)
			}
			g.gz = nil // guard against double-close if finish() is called again
		}
		return
	}
	g.flushBuffered()
	if g.gz != nil {
		if err := g.gz.Close(); err != nil {
			g.logger.Error("gzip: failed to close compressed stream", "error", err)
		}
		g.gz = nil
	}
}

func (g *gzipResponseWriter) flushBuffered() {
	ct := g.ResponseWriter.Header().Get("Content-Type")
	alreadyEncoded := g.ResponseWriter.Header().Get("Content-Encoding") != ""

	if !alreadyEncoded && len(g.buf) >= g.minSizeBytes && isCompressible(ct) {
		g.armGzip()
	} else {
		g.ResponseWriter.Header().Del("Content-Encoding")
		g.ResponseWriter.WriteHeader(g.status)
	}
	g.headersDone = true
	if len(g.buf) > 0 {
		_, _ = g.writeThrough(g.buf)
	}
}

func (g *gzipResponseWriter) armGzip() {
	g.ResponseWriter.Header().Set("Content-Encoding", "gzip")
	g.ResponseWriter.Header().Del("Content-Length") // length changes after compression
	g.ResponseWriter.WriteHeader(g.status)
	// NewWriterLevel only errors on out-of-range level; level is clamped in newGzipResponseWriter.
	gz, _ := gzip.NewWriterLevel(g.ResponseWriter, g.level)
	g.gz = gz
}

func (g *gzipResponseWriter) writeThrough(b []byte) (int, error) {
	if g.gz != nil {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// isCompressible reports whether the Content-Type is worth compressing.
// Binary formats (images, video, audio, zip) are already compressed and
// should be excluded to avoid CPU waste and potential size increase.
func isCompressible(ct string) bool {
	ct = strings.ToLower(strings.SplitN(ct, ";", 2)[0])
	ct = strings.TrimSpace(ct)
	switch {
	case strings.HasPrefix(ct, "text/"):
		return true
	case ct == "application/json",
		ct == "application/xml",
		ct == "application/javascript",
		ct == "application/x-www-form-urlencoded",
		ct == "image/svg+xml":
		return true
	default:
		return false
	}
}

// gzipResponseWriter must satisfy io.Writer so callers that type-assert
// http.ResponseWriter to io.Writer (e.g. some middleware) still work.
var _ io.Writer = (*gzipResponseWriter)(nil)

// JWTMiddleware returns middleware that validates Bearer tokens and injects
// verified identity claims as upstream-facing headers.
//
// Design: Decorator pattern — wraps the next handler and adds authentication
// as a cross-cutting concern without the proxy or application layer knowing
// anything about JWT.
//
// Strategy pattern: verifier is a ports.TokenVerifier — callers inject the
// concrete algorithm (HS256 or JWKS/RS256) without the middleware knowing which.
//
// Forward-auth pattern:
//   - On a valid token, the middleware strips any client-provided auth headers
//     (to prevent spoofing) and replaces them with verified values derived from
//     the JWT claims. Upstreams trust these headers as pre-validated identity.
//   - On an invalid or missing token, it returns 401 and the request never
//     reaches the proxy.
//
// publicPaths lists path prefixes that skip token validation. Auth headers are
// still stripped on public paths to prevent clients from spoofing identity to
// upstreams even on unauthenticated endpoints.
func JWTMiddleware(verifier ports.TokenVerifier, publicPaths []string, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip any client-provided identity headers unconditionally.
			// A client must never be able to inject X-Auth-* values that
			// upstreams would interpret as pre-validated gateway identity.
			r.Header.Del("X-Auth-Subject")
			r.Header.Del("X-Auth-Scope")
			r.Header.Del("X-Auth-Roles")

			// Public paths bypass token validation; the stripping above
			// still applies so malicious clients cannot spoof identity.
			if isPublicPath(r.URL.Path, publicPaths) {
				next.ServeHTTP(w, r)
				return
			}

			raw, ok := extractBearerToken(r)
			if !ok {
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "unauthorized"))
				return
			}

			claims, err := verifier.Verify(raw)
			if err != nil {
				// Log at debug level — 401s are expected traffic and should
				// not flood the error log in production.
				if errors.Is(err, jwtutil.ErrTokenExpired) {
					logger.Debug("jwt expired", "path", r.URL.Path)
				} else {
					logger.Debug("jwt invalid", "path", r.URL.Path, "error", err)
				}
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "unauthorized"))
				return
			}

			// Inject verified identity as upstream-facing headers.
			// Upstreams receive these as trusted facts from the gateway; they
			// do not need to validate JWT themselves (forward-auth pattern).
			r.Header.Set("X-Auth-Subject", claims.Subject)
			r.Header.Set("X-Auth-Scope", claims.Scope)
			if len(claims.Roles) > 0 {
				r.Header.Set("X-Auth-Roles", strings.Join(claims.Roles, ","))
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken extracts the token string from an "Authorization: Bearer <token>"
// header. Returns the raw token and true on success; empty string and false if the
// header is absent or malformed.
func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	token := strings.TrimSpace(auth[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// isPublicPath reports whether path matches any of the given prefixes.
func isPublicPath(path string, publicPaths []string) bool {
	for _, prefix := range publicPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
